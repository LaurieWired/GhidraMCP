"""Command-line entry point for the ghidra-mcp server."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
from pathlib import Path

from ghidra_mcp.backend import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_GHIDRA_SERVER,
    DEFAULT_READ_TIMEOUT,
    DeferredBackend,
    GhidraBackend,
)
from ghidra_mcp.server import create_server

logger = logging.getLogger("ghidra_mcp")

TRANSPORTS = ["stdio", "streamable-http", "sse"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ghidra-mcp", description="MCP server for Ghidra")
    parser.add_argument(
        "--ghidra-server",
        default=DEFAULT_GHIDRA_SERVER,
        help=f"GhidraMCP backend URL in GUI mode (default: {DEFAULT_GHIDRA_SERVER})",
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=TRANSPORTS,
        help="MCP transport (default: stdio). 'sse' is deprecated; use 'streamable-http'.",
    )
    parser.add_argument(
        "--mcp-host",
        default="127.0.0.1",
        help="Bind host for HTTP transports (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--mcp-port", type=int, default=8081, help="Bind port for HTTP transports (default: 8081)"
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help=f"Backend connect timeout in seconds (default: {DEFAULT_CONNECT_TIMEOUT})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_READ_TIMEOUT,
        help=f"Backend read timeout in seconds (default: {DEFAULT_READ_TIMEOUT})",
    )

    headless = parser.add_argument_group(
        "headless mode", "Run Ghidra in-process via PyGhidra instead of connecting to the GUI"
    )
    headless.add_argument("--headless", action="store_true", help="Enable headless mode")
    headless.add_argument("--binary", type=Path, help="Binary to import/open (required)")
    headless.add_argument(
        "--project",
        type=Path,
        help="Ghidra project directory to create/reuse (default: a temporary project)",
    )
    headless.add_argument(
        "--project-name", help="Ghidra project name (default: <binary>_ghidra_mcp)"
    )
    headless.add_argument(
        "--no-analyze", action="store_true", help="Skip auto-analysis of the program"
    )
    save = headless.add_mutually_exclusive_group()
    save.add_argument(
        "--save",
        dest="save",
        action="store_true",
        default=None,
        help="Save changes on exit (default when --project is given)",
    )
    save.add_argument(
        "--discard",
        dest="save",
        action="store_false",
        help="Discard changes on exit (default for temporary projects)",
    )
    headless.add_argument(
        "--ghidra-install-dir",
        type=Path,
        help="Ghidra installation (default: $GHIDRA_INSTALL_DIR or the last-run install)",
    )
    headless.add_argument(
        "--extension-jar",
        type=Path,
        help="GhidraMCP.jar to use instead of the extension installed in Ghidra",
    )
    headless.add_argument("--language", help="Ghidra language ID, e.g. x86:LE:64:default")
    headless.add_argument("--compiler", help="Ghidra compiler spec ID, e.g. gcc")
    headless.add_argument(
        "--ready-timeout",
        type=float,
        default=30.0,
        help="How long a tool call waits for loading/analysis before failing (default: 30)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.headless and args.binary is None:
        parser.error("--headless requires --binary")

    # stdout carries the MCP stdio stream, so logs must go to stderr.
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr, format="%(levelname)s:%(name)s:%(message)s"
    )
    if args.transport == "sse":
        logger.warning("The 'sse' transport is deprecated; use 'streamable-http'.")

    if args.headless:
        run_headless(args)
    else:
        run_gui(args)


def run_gui(args: argparse.Namespace) -> None:
    backend = GhidraBackend(args.ghidra_server, args.connect_timeout, args.timeout)
    health = backend.health()
    if health is None:
        logger.warning(
            "GhidraMCP backend at %s is not reachable yet; tools will fail until Ghidra is "
            "running with the plugin enabled.",
            backend.base_url,
        )
        capabilities = None
    else:
        program = (health.get("program") or {}).get("name", "no program open")
        logger.info(
            "Connected to Ghidra %s (%s mode): %s",
            health.get("ghidra_version"),
            health.get("mode"),
            program,
        )
        capabilities = set(health.get("capabilities", []))
    mcp = create_server(backend, args.mcp_host, args.mcp_port, capabilities)
    serve(mcp, args)


def run_headless(args: argparse.Namespace) -> None:
    from ghidra_mcp.headless import HeadlessError, HeadlessOptions, HeadlessSession, protect_stdout

    if args.transport == "stdio":
        protect_stdout()

    options = HeadlessOptions(
        binary=args.binary.expanduser().resolve(),
        project_dir=args.project,
        project_name=args.project_name,
        analyze=not args.no_analyze,
        save=args.save,
        ghidra_install_dir=args.ghidra_install_dir,
        extension_jar=args.extension_jar,
        language=args.language,
        compiler=args.compiler,
    )
    backend = DeferredBackend(args.connect_timeout, args.timeout, args.ready_timeout)
    session = HeadlessSession(options, backend)
    try:
        session.start()
    except HeadlessError as e:
        logger.error("%s", e)
        sys.exit(1)

    mcp = create_server(backend, args.mcp_host, args.mcp_port, capabilities=set())

    def serve_then_stop() -> None:
        try:
            serve(mcp, args)
        except Exception:
            logger.exception("MCP server failed")
        finally:
            session.request_stop()

    # Ghidra work stays on the main thread (see HeadlessSession); MCP is served alongside it so
    # clients can initialize while the program is still being analyzed.
    threading.Thread(target=serve_then_stop, name="ghidra-mcp-server", daemon=True).start()
    exit_code = 0
    try:
        session.run()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.close()
        except Exception:
            logger.exception("Error while closing the Ghidra session")
            exit_code = 1
    # Lingering non-daemon JVM threads can block interpreter shutdown, so exit directly once the
    # program has been saved or released.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):  # the stdio transport may already have closed stdout
            pass
    os._exit(exit_code)


def serve(mcp, args: argparse.Namespace) -> None:
    if args.transport != "stdio":
        path = "/mcp" if args.transport == "streamable-http" else "/sse"
        logger.info("Serving MCP on http://%s:%d%s", args.mcp_host, args.mcp_port, path)
    try:
        mcp.run(transport=args.transport)
    except KeyboardInterrupt:
        pass
