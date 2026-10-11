"""Headless mode: load a binary with PyGhidra and serve it through the same Java backend."""

from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from ghidra_mcp.backend import DeferredBackend

logger = logging.getLogger("ghidra_mcp.headless")

RESTRICTED_EXTENSIONS_PROPERTY = "ghidra.extensions.classpath.restricted"


class HeadlessError(RuntimeError):
    pass


@dataclass
class HeadlessOptions:
    binary: Path
    project_dir: Path | None = None
    project_name: str | None = None
    analyze: bool = True
    save: bool | None = None  # None: save if the project is user-provided
    ghidra_install_dir: Path | None = None
    extension_jar: Path | None = None
    language: str | None = None
    compiler: str | None = None


def protect_stdout() -> None:
    """Points file descriptor 1 at stderr so JVM/Ghidra output can't corrupt the MCP stdio stream,
    and gives Python's sys.stdout a private duplicate of the original stdout."""
    sys.stdout.flush()
    mcp_stdout = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = os.fdopen(mcp_stdout, "w", encoding="utf-8", buffering=1)


class HeadlessSession:
    """Owns the JVM-side state for one headless program: project, program, backend server.

    Ghidra's project APIs hang when first used from a Python thread other than the one that
    started the JVM, so start(), run() and close() must all be called on the main thread. The MCP
    server runs on another thread and calls request_stop() when it exits.
    """

    def __init__(self, options: HeadlessOptions, backend: DeferredBackend):
        self.options = options
        self.backend = backend
        self._temp_dir: Path | None = None
        self._project = None
        self._program = None
        self._consumer = None
        self._server = None
        self._monitor = None
        self._closing = threading.Event()

    # ---- lifecycle -------------------------------------------------------------------------

    def start(self) -> None:
        """Validates options and starts the JVM."""
        binary = self.options.binary
        if not binary.is_file():
            raise HeadlessError(f"Binary not found: {binary}")
        self._start_jvm()

    def load(self) -> None:
        """Imports (if needed), analyzes and serves the program. Raises on failure."""
        self._open_program()
        self._serve()

    def run(self) -> None:
        """Loads the program, then blocks until request_stop(). Load failures are reported to
        tool calls instead of raised."""
        try:
            self.load()
        except Exception as e:
            if not self._closing.is_set():
                logger.exception("Headless startup failed")
                self.backend.set_failed(f"{e.__class__.__name__}: {e}")
        while not self._closing.wait(0.5):
            pass

    def request_stop(self) -> None:
        """Thread-safe: interrupts analysis and makes run() return."""
        self._closing.set()
        monitor = self._monitor
        if monitor is not None:
            monitor.cancel()

    def close(self) -> None:
        self._closing.set()
        try:
            if self._server is not None:
                self._server.stop()
            if self._program is not None:
                if self._should_save() and self._program.isChanged():
                    logger.info("Saving %s", self._program.getName())
                    self._program.save("ghidra-mcp headless session", self._task_monitor())
                elif self._program.isChanged():
                    logger.info("Discarding unsaved changes to %s", self._program.getName())
                self._program.release(self._consumer)
            if self._project is not None:
                self._project.close()
        finally:
            if self._temp_dir is not None:
                shutil.rmtree(self._temp_dir, ignore_errors=True)

    # ---- internals -------------------------------------------------------------------------

    def _should_save(self) -> bool:
        if self.options.save is not None:
            return self.options.save
        return self.options.project_dir is not None

    def _start_jvm(self) -> None:
        try:
            from pyghidra.launcher import HeadlessPyGhidraLauncher
        except ImportError as e:
            raise HeadlessError(
                "Headless mode needs PyGhidra. Install with: pip install 'ghidra-mcp[headless]' "
                "(or uvx --from 'ghidra-mcp[headless]' ...)"
            ) from e

        launcher = HeadlessPyGhidraLauncher(install_dir=self.options.ghidra_install_dir)
        jar = self._explicit_extension_jar()
        if jar is not None:
            # Installed extensions are otherwise on the system classpath ahead of class files
            # added after startup, so an installed GhidraMCP would shadow the requested jar.
            launcher.add_vmargs(f"-D{RESTRICTED_EXTENSIONS_PROPERTY}=true")
            launcher.add_class_files(str(jar))
        logger.info("Starting Ghidra from %s", launcher.install_dir)
        launcher.start()

        import jpype

        try:
            backend_class = jpype.JClass("com.lauriewired.ghidramcp.headless.HeadlessBackend")
        except TypeError as e:
            raise HeadlessError(
                "The GhidraMCP extension classes were not found. Install the GhidraMCP extension "
                "in Ghidra or pass --extension-jar /path/to/GhidraMCP.jar"
            ) from e

        loaded = self._class_location(backend_class)
        logger.info("Using GhidraMCP classes from %s", loaded or "<unknown>")
        if jar is not None and loaded is not None and loaded != jar:
            raise HeadlessError(f"Requested extension jar {jar} but Ghidra loaded {loaded}")

    def _explicit_extension_jar(self) -> Path | None:
        """The jar requested via option or environment, or None to use the installed extension."""
        explicit = self.options.extension_jar or os.environ.get("GHIDRA_MCP_EXTENSION_JAR")
        if not explicit:
            return None
        jar = Path(explicit).expanduser().resolve()
        if not jar.is_file():
            raise HeadlessError(f"Extension jar not found: {jar}")
        return jar

    @staticmethod
    def _class_location(java_class) -> Path | None:
        try:
            from java.io import File

            url = java_class.class_.getProtectionDomain().getCodeSource().getLocation()
            return Path(str(File(url.toURI()).getCanonicalPath()))
        except Exception:  # noqa: BLE001 - diagnostics only
            return None

    def _task_monitor(self):
        from ghidra.util.task import TaskMonitor

        return TaskMonitor.DUMMY

    def _open_project(self):
        import pyghidra

        opts = self.options
        if opts.project_dir is not None:
            project_dir = opts.project_dir.expanduser().resolve()
            project_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="ghidra-mcp-"))
            project_dir = self._temp_dir
        name = opts.project_name or f"{opts.binary.stem}_ghidra_mcp"
        try:
            return pyghidra.open_project(str(project_dir), name, create=True)
        except Exception as e:
            if "lock" in str(e).lower() or "LockException" in type(e).__name__:
                raise HeadlessError(
                    f"Project '{name}' in {project_dir} is locked; close it in the Ghidra GUI "
                    f"(or any other headless session) first"
                ) from e
            raise

    def _open_program(self) -> None:
        import pyghidra
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.util.task import TaskMonitorAdapter

        opts = self.options
        self.backend.status = "opening project"
        self._project = self._open_project()
        program_path = "/" + opts.binary.name
        imported = False
        if self._project.getProjectData().getFile(program_path) is None:
            self.backend.status = "importing"
            logger.info("Importing %s", opts.binary)
            loader = pyghidra.program_loader().project(self._project).source(str(opts.binary))
            loader = loader.name(opts.binary.name)
            if opts.language:
                loader = loader.language(opts.language)
            if opts.compiler:
                loader = loader.compiler(opts.compiler)
            results = loader.load()
            try:
                program_path = results.getPrimary().save(self._task_monitor()).getPathname()
            finally:
                results.close()
            imported = True
        else:
            logger.info("Opening existing program %s from the project", program_path)

        self._program, self._consumer = pyghidra.consume_program(self._project, program_path)

        if opts.analyze and (imported or not GhidraProgramUtilities.isAnalyzed(self._program)):
            self.backend.status = "analyzing"
            logger.info("Analyzing %s (this can take a while)", self._program.getName())
            self._monitor = TaskMonitorAdapter(True)
            pyghidra.analyze(self._program, self._monitor)
            self._monitor = None
            # pyghidra.analyze cancels its monitor on completion, so check our own flag.
            if self._closing.is_set():
                raise HeadlessError("Analysis was interrupted by shutdown")

    def _serve(self) -> None:
        import jpype

        backend_cls = jpype.JClass("com.lauriewired.ghidramcp.headless.HeadlessBackend")
        self._server = backend_cls.start(self._program, 0)
        url = f"http://127.0.0.1:{self._server.getPort()}/"
        logger.info("Serving %s on %s", self._program.getName(), url)
        self.backend.set_ready(url)
