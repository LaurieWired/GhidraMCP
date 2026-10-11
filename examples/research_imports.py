# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "ghidra-mcp @ git+https://github.com/LaurieWired/GhidraMCP",
#     "mcp>=1.30,<2",
#     "httpx>=0.28,<1",
# ]
# ///
"""Read local imports and research explicitly selected public API documentation."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from datetime import timedelta

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

PARALLEL_URL = "https://search.parallel.ai/mcp"
USER_AGENT = "GhidraMCP/research-imports-example"
CALL_TIMEOUT = timedelta(seconds=90)


async def call_tool(session: ClientSession, name: str, arguments: dict) -> object:
    result = await session.call_tool(name, arguments)
    if result.isError:
        message = "\n".join(c.text for c in result.content if c.type == "text")
        raise RuntimeError(f"{name}: {message}")
    if result.structuredContent is not None:
        return result.structuredContent
    # Some servers return JSON as text rather than structured content.
    if len(result.content) == 1 and result.content[0].type == "text":
        try:
            return json.loads(result.content[0].text)
        except ValueError:
            return result.content[0].text
    return [c.model_dump(mode="json") for c in result.content]


def emit(section: str, result: object) -> None:
    print(json.dumps({section: result}, ensure_ascii=False), flush=True)


async def run(args: argparse.Namespace) -> None:
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ghidra_mcp", "--ghidra-server", args.ghidra_server],
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=CALL_TIMEOUT) as ghidra:
            await ghidra.initialize()
            emit("program", await call_tool(ghidra, "get_program_info", {}))
            emit("imports", await call_tool(ghidra, "list_imports", {"offset": args.offset}))

    if not args.query and not args.fetch_url:
        return

    # Only explicit CLI inputs go to Parallel, never results from the local binary.
    session_id = str(uuid.uuid4())
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, timeout=90, trust_env=False,
    ) as http:
        async with streamable_http_client(PARALLEL_URL, http_client=http) as (read, write, _):
            async with ClientSession(read, write, read_timeout_seconds=CALL_TIMEOUT) as parallel:
                await parallel.initialize()
                tools = {tool.name for tool in (await parallel.list_tools()).tools}
                required = ({"web_search"} if args.query else set()) | (
                    {"web_fetch"} if args.fetch_url else set()
                )
                if not required <= tools:
                    raise RuntimeError(f"Parallel is missing tools: {sorted(required - tools)}")
                if args.query:
                    emit("search", await call_tool(parallel, "web_search", {
                        "objective": "Find official API documentation for: " + "; ".join(args.query),
                        "search_queries": args.query,
                        "session_id": session_id,
                    }))
                if args.fetch_url:
                    result = await call_tool(parallel, "web_fetch", {
                        "urls": [args.fetch_url], "session_id": session_id,
                    })
                    emit("fetch", result)
                    if isinstance(result, dict) and result.get("errors"):
                        raise RuntimeError("Page fetching reported errors; see the fetch output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-server", default="http://127.0.0.1:8080/")
    parser.add_argument("--offset", type=int, default=0, help="Import page offset (100 per page)")
    parser.add_argument("--query", action="append", help="Public API search query; repeat for variants")
    parser.add_argument("--fetch-url", help="Public documentation URL to fetch")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.offset < 0:
        parser.error("--offset must be nonnegative")
    if args.query and any(not q.strip() for q in args.query):
        parser.error("--query must not be blank")
    if args.fetch_url and httpx.URL(args.fetch_url).scheme not in ("http", "https"):
        parser.error("--fetch-url must be an HTTP or HTTPS URL")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
