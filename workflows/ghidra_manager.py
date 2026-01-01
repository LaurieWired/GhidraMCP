#!/usr/bin/env python3
"""
Ghidra Process Manager for Autonomous Workflows

Provides tools to:
- Check if Ghidra is running and MCP server is available
- Gracefully close Ghidra
- Start Ghidra with a specific project and binary
- Wait for MCP server to become available
- Auto-restart on connection failure

This enables the continuous improvement loop to run truly autonomously
by recovering from Ghidra crashes or hangs.
"""

import subprocess
import time
import os
import sys
import json
import logging
import requests
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime

# Setup logging
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# File handler for persistent logs
log_file = LOG_DIR / f"ghidra_manager_{datetime.now().strftime('%Y%m%d')}.log"
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# Console handler for stdout
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(message)s'))

# Configure logger
logger = logging.getLogger('ghidra_manager')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Default configuration
DEFAULT_GHIDRA_PATH = r"F:\ghidra_11.4.2"
DEFAULT_MCP_PORT = 8089  # GhidraMCP default port
DEFAULT_MCP_HOST = "127.0.0.1"
MCP_STARTUP_TIMEOUT = 120  # seconds to wait for MCP server after Ghidra starts
GHIDRA_SHUTDOWN_TIMEOUT = 60  # seconds to wait for graceful shutdown (Ghidra needs time to save)

# Config file path
CONFIG_FILE = Path(__file__).parent / ".ghidra_manager_config.json"


class GhidraState(Enum):
    """Current state of Ghidra"""
    NOT_RUNNING = "not_running"
    STARTING = "starting"
    RUNNING_NO_MCP = "running_no_mcp"  # Ghidra running but MCP not available
    RUNNING_WITH_MCP = "running_with_mcp"  # Full operational state
    SHUTTING_DOWN = "shutting_down"


@dataclass
class GhidraConfig:
    """Configuration for Ghidra management"""
    ghidra_path: str = DEFAULT_GHIDRA_PATH
    mcp_host: str = DEFAULT_MCP_HOST
    mcp_port: int = DEFAULT_MCP_PORT
    default_project: Optional[str] = None  # e.g., "F:\\GhidraProjects\\PD2.gpr"
    default_binary: Optional[str] = None   # e.g., "Game.exe" or full path
    auto_start_mcp: bool = True
    startup_timeout: int = MCP_STARTUP_TIMEOUT

    def save(self):
        """Save config to disk"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> 'GhidraConfig':
        """Load config from disk or return defaults"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                    return cls(**data)
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()


class GhidraManager:
    """
    Manages the Ghidra process lifecycle for autonomous workflows.

    Example usage:
        manager = GhidraManager()

        # Check current state
        state = manager.get_state()

        # Ensure Ghidra is running with MCP
        if state != GhidraState.RUNNING_WITH_MCP:
            success = manager.ensure_running(
                project="F:\\GhidraProjects\\PD2.gpr",
                binary="D2Win.dll"
            )

        # Or restart completely
        manager.restart(project="...", binary="...")
    """

    def __init__(self, config: Optional[GhidraConfig] = None):
        self.config = config or GhidraConfig.load()
        self._last_state = None
        self._state_check_time = 0

    @property
    def mcp_url(self) -> str:
        """Get the MCP server URL"""
        return f"http://{self.config.mcp_host}:{self.config.mcp_port}"

    def get_state(self, force_check: bool = False) -> GhidraState:
        """
        Get current Ghidra state.

        Checks:
        1. Is there a Java process that looks like Ghidra?
        2. Is the MCP server responding?

        Results are cached for 2 seconds unless force_check=True.
        """
        now = time.time()
        if not force_check and self._last_state and (now - self._state_check_time) < 2:
            return self._last_state

        # Check if MCP server is responding
        mcp_available = self._check_mcp_server()

        # Check for Ghidra process
        ghidra_running = self._check_ghidra_process()

        if mcp_available:
            state = GhidraState.RUNNING_WITH_MCP
        elif ghidra_running:
            state = GhidraState.RUNNING_NO_MCP
        else:
            state = GhidraState.NOT_RUNNING

        self._last_state = state
        self._state_check_time = now
        return state

    def _check_mcp_server(self) -> bool:
        """Check if MCP server is responding"""
        try:
            # Use /methods endpoint since root returns 404
            response = requests.get(
                f"{self.mcp_url}/methods",
                timeout=5
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def _check_ghidra_process(self) -> bool:
        """Check if Ghidra process is running (Windows-specific)"""
        try:
            # Use tasklist to find javaw processes
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq javaw.exe', '/FO', 'CSV', '/NH'],
                capture_output=True,
                text=True,
                timeout=10
            )
            # If javaw.exe is in the output, Ghidra might be running
            # This is imperfect but reasonable for our needs
            return 'javaw.exe' in result.stdout
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            # tasklist not available, try alternative
            return self._check_ghidra_process_powershell()

    def _check_ghidra_process_powershell(self) -> bool:
        """Alternative process check using PowerShell"""
        try:
            # Match both "Ghidra*" (project manager) and "CodeBrowser*" (active code window)
            result = subprocess.run(
                ['powershell', '-Command',
                 "Get-Process | Where-Object { $_.ProcessName -eq 'javaw' -and ($_.MainWindowTitle -like 'Ghidra*' -or $_.MainWindowTitle -like 'CodeBrowser*') } | Select-Object -First 1"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def close_ghidra(self, force: bool = False, timeout: int = None) -> bool:
        """
        Close Ghidra gracefully by sending a close command to the window.

        This sends WM_CLOSE to the Ghidra window, which triggers Ghidra's
        normal shutdown process including saving the project. This is NOT
        a force-kill - Ghidra will save all changes before closing.

        Args:
            force: If True, force-kill the process WITHOUT saving (dangerous!)
                   Only use this if Ghidra is hung and you don't care about data loss.
            timeout: How long to wait for graceful shutdown (default: 60s)
                     Ghidra may take a while to save large projects.

        Returns:
            True if Ghidra was closed successfully (or wasn't running)
        """
        timeout = timeout or GHIDRA_SHUTDOWN_TIMEOUT

        if force:
            logger.warning(f"Force-closing Ghidra WITHOUT saving! (timeout={timeout}s)")
        else:
            logger.info(f"Closing Ghidra gracefully (timeout={timeout}s)...")
            logger.info("  Ghidra will save the project before closing.")

        # Send graceful close signal (WM_CLOSE to window)
        # Match both "Ghidra*" (project manager) and "CodeBrowser*" (active code window)
        ps_script = '''
        $ghidra = Get-Process | Where-Object {
            $_.ProcessName -eq 'javaw' -and ($_.MainWindowTitle -like 'Ghidra*' -or $_.MainWindowTitle -like 'CodeBrowser*')
        }
        if ($ghidra) {
            $ghidra | ForEach-Object {
                Write-Host "Found Ghidra PID: $($_.Id) - Window: $($_.MainWindowTitle)"
                $_.CloseMainWindow() | Out-Null
                Write-Host "Sent close command to Ghidra (PID $($_.Id))"
            }
            exit 0
        } else {
            Write-Host "No Ghidra process found"
            exit 1
        }
        '''

        try:
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=15
            )
            logger.info(result.stdout.strip())

            if result.returncode != 0:
                logger.info("Ghidra is not running - nothing to close")
                return True  # Already closed

            # Wait for graceful shutdown - Ghidra needs time to save
            # Ghidra may have multiple windows (CodeBrowser, Project Manager, etc.)
            # We keep checking and sending close commands until all windows are closed
            logger.info("Waiting for Ghidra to save and close...")
            last_close_attempt = 0
            for i in range(timeout):
                time.sleep(1)
                if not self._check_ghidra_process():
                    logger.info(f"Ghidra closed successfully after {i+1}s (project saved)")
                    self._last_state = None
                    return True

                # Every 5 seconds, try sending another close command
                # This handles Ghidra's multiple windows (CodeBrowser closes, Project Manager stays)
                if (i + 1) - last_close_attempt >= 5:
                    retry_result = subprocess.run(
                        ['powershell', '-Command', ps_script],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    if retry_result.returncode == 0:
                        # Found more windows, sent close
                        for line in retry_result.stdout.strip().split('\n'):
                            if line.strip():
                                logger.info(f"  {line.strip()}")
                        last_close_attempt = i + 1
                    # else: no more windows found, just waiting for process to exit

                # Progress updates every 10 seconds
                if (i + 1) % 10 == 0:
                    logger.info(f"  Still waiting for Ghidra to finish saving... ({i+1}/{timeout}s)")

            # Timeout reached - Ghidra is still running
            if force:
                logger.warning(f"Timeout after {timeout}s - force-killing Ghidra (DATA MAY BE LOST!)...")
                force_script = '''
                Get-Process | Where-Object {
                    $_.ProcessName -eq 'javaw' -and ($_.MainWindowTitle -like 'Ghidra*' -or $_.MainWindowTitle -like 'CodeBrowser*')
                } | Stop-Process -Force
                '''
                subprocess.run(
                    ['powershell', '-Command', force_script],
                    capture_output=True,
                    timeout=10
                )
                time.sleep(2)
                self._last_state = None
                return not self._check_ghidra_process()
            else:
                # Don't force-kill - report that it's still running
                # This likely means Ghidra is showing a dialog (e.g., "Save project?")
                logger.warning(f"Ghidra did not close after {timeout}s.")
                logger.warning("  This usually means Ghidra is showing a dialog box.")
                logger.warning("  Check Ghidra and respond to any dialogs (Save/Don't Save/Cancel).")
                logger.info("  TIP: Ghidra auto-saves periodically, so 'Don't Save' is usually safe.")
                logger.info("  Use force=True only if Ghidra is completely frozen.")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Timeout while sending close command to Ghidra")
            return False
        except Exception as e:
            logger.error(f"Error closing Ghidra: {e}")
            return False

    def start_ghidra(
        self,
        project: Optional[str] = None,
        binary: Optional[str] = None,
        wait_for_mcp: bool = True
    ) -> Tuple[bool, str]:
        """
        Start Ghidra with optional project and binary.

        Args:
            project: Path to .gpr project file (e.g., "F:\\GhidraProjects\\PD2.gpr")
            binary: Binary to open (filename if in project, or full path)
            wait_for_mcp: If True, wait for MCP server to become available

        Returns:
            Tuple of (success, message)
        """
        ghidra_bat = Path(self.config.ghidra_path) / "ghidraRun.bat"

        if not ghidra_bat.exists():
            return False, f"Ghidra not found at: {ghidra_bat}"

        # Build command
        cmd = [str(ghidra_bat)]

        project = project or self.config.default_project
        binary = binary or self.config.default_binary

        if project:
            cmd.append(project)
            if binary:
                cmd.extend(["-open", binary])

        logger.info(f"Starting Ghidra: {' '.join(cmd)}")

        try:
            # Start Ghidra (don't wait for it to finish)
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
            )

            logger.info(f"Ghidra process started (PID: {process.pid})")

            if wait_for_mcp:
                return self._wait_for_mcp()
            else:
                return True, "Ghidra started (not waiting for MCP)"

        except Exception as e:
            return False, f"Failed to start Ghidra: {e}"

    def _wait_for_mcp(self) -> Tuple[bool, str]:
        """Wait for MCP server to become available"""
        timeout = self.config.startup_timeout
        logger.info(f"Waiting for MCP server (timeout: {timeout}s)...")

        start_time = time.time()
        check_interval = 2  # seconds between checks

        while (time.time() - start_time) < timeout:
            elapsed = int(time.time() - start_time)

            if self._check_mcp_server():
                logger.info(f"MCP server available after {elapsed}s")
                self._last_state = GhidraState.RUNNING_WITH_MCP
                return True, f"Ghidra running with MCP (startup took {elapsed}s)"

            # Also check that Ghidra process is still running
            if elapsed > 10 and not self._check_ghidra_process():
                return False, "Ghidra process terminated unexpectedly"

            logger.info(f"Waiting for MCP server... ({elapsed}/{timeout}s)")
            time.sleep(check_interval)

        # Timeout
        if self._check_ghidra_process():
            return False, f"Ghidra running but MCP not available after {timeout}s. Enable the plugin manually: Tools > GhidraMCP > Start MCP Server"
        else:
            return False, "Ghidra failed to start"

    def restart(
        self,
        project: Optional[str] = None,
        binary: Optional[str] = None,
        force_close: bool = False,
        close_timeout: int = None
    ) -> Tuple[bool, str]:
        """
        Restart Ghidra completely.

        This performs a graceful restart:
        1. Sends close command to Ghidra (triggers save)
        2. Waits for Ghidra to save and close
        3. Starts Ghidra fresh with the specified project/binary

        Args:
            project: Project to open after restart
            binary: Binary to open after restart
            force_close: If True, force-kill without saving (dangerous!)
            close_timeout: How long to wait for graceful close (default: 60s)

        Returns:
            Tuple of (success, message)
        """
        logger.info("=" * 50)
        logger.info("RESTARTING GHIDRA")
        logger.info("=" * 50)

        # Close existing instance
        state = self.get_state(force_check=True)
        if state != GhidraState.NOT_RUNNING:
            logger.info(f"Current state: {state.value}")
            closed = self.close_ghidra(force=force_close, timeout=close_timeout)
            if not closed:
                if force_close:
                    return False, "Failed to close Ghidra even with force=True"
                else:
                    return False, "Ghidra did not close in time. It may be saving or showing a dialog. Try again or use force_close=True (will lose unsaved changes)."
            time.sleep(3)  # Extra wait after close to ensure file locks are released

        # Start fresh
        return self.start_ghidra(project=project, binary=binary)

    def ensure_running(
        self,
        project: Optional[str] = None,
        binary: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Ensure Ghidra is running with MCP available.

        If already running with MCP, returns immediately.
        If running without MCP, waits for MCP.
        If not running, starts Ghidra.

        Args:
            project: Project to open if starting fresh
            binary: Binary to open if starting fresh

        Returns:
            Tuple of (success, message)
        """
        state = self.get_state(force_check=True)

        if state == GhidraState.RUNNING_WITH_MCP:
            return True, "Ghidra already running with MCP"

        if state == GhidraState.RUNNING_NO_MCP:
            print("Ghidra running but MCP not available, waiting...")
            return self._wait_for_mcp()

        # Not running, start it
        return self.start_ghidra(project=project, binary=binary)

    def get_program_info(self) -> Optional[Dict[str, Any]]:
        """Get info about the currently loaded program in Ghidra"""
        try:
            response = requests.get(
                f"{self.mcp_url}/methods/get_program_info",
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            pass
        return None

    def health_check(self) -> Dict[str, Any]:
        """
        Perform a comprehensive health check.

        Returns dict with:
        - state: Current GhidraState
        - mcp_available: Boolean
        - program_loaded: Name of loaded program (or None)
        - recommendations: List of suggested actions
        """
        state = self.get_state(force_check=True)
        program_info = self.get_program_info() if state == GhidraState.RUNNING_WITH_MCP else None

        result = {
            "state": state.value,
            "mcp_available": state == GhidraState.RUNNING_WITH_MCP,
            "program_loaded": None,
            "recommendations": []
        }

        if program_info and program_info.get("success"):
            data = program_info.get("data", "")
            if "Program:" in data:
                # Extract program name from response
                for line in data.split('\n'):
                    if line.startswith("Program:"):
                        result["program_loaded"] = line.split(":", 1)[1].strip()
                        break

        # Generate recommendations
        if state == GhidraState.NOT_RUNNING:
            result["recommendations"].append("Start Ghidra with manager.start_ghidra(project, binary)")
        elif state == GhidraState.RUNNING_NO_MCP:
            result["recommendations"].append("Enable MCP: Tools > GhidraMCP > Start MCP Server")
            result["recommendations"].append("Or restart: manager.restart(project, binary)")
        elif not result["program_loaded"]:
            result["recommendations"].append("No program loaded - open a binary in Ghidra")

        return result


# Convenience functions for use without instantiating the class
_manager_instance = None

def get_manager() -> GhidraManager:
    """Get singleton manager instance"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = GhidraManager()
    return _manager_instance


def check_ghidra() -> Dict[str, Any]:
    """Quick health check - returns status dict"""
    return get_manager().health_check()


def restart_ghidra(
    project: Optional[str] = None,
    binary: Optional[str] = None,
    force: bool = False
) -> Tuple[bool, str]:
    """Restart Ghidra with optional project/binary"""
    return get_manager().restart(project=project, binary=binary, force_close=force)


def ensure_ghidra(
    project: Optional[str] = None,
    binary: Optional[str] = None
) -> Tuple[bool, str]:
    """Ensure Ghidra is running with MCP available"""
    return get_manager().ensure_running(project=project, binary=binary)


def close_ghidra(force: bool = False) -> bool:
    """Close Ghidra"""
    return get_manager().close_ghidra(force=force)


def configure_defaults(
    ghidra_path: Optional[str] = None,
    project: Optional[str] = None,
    binary: Optional[str] = None,
    mcp_port: int = None
) -> GhidraConfig:
    """
    Configure default Ghidra settings.

    These are saved to disk and used when no arguments are provided.

    Example:
        configure_defaults(
            ghidra_path=r"F:\\ghidra_11.4.2",
            project=r"F:\\GhidraProjects\\PD2.gpr",
            binary="D2Win.dll"
        )
    """
    manager = get_manager()

    if ghidra_path:
        manager.config.ghidra_path = ghidra_path
    if project:
        manager.config.default_project = project
    if binary:
        manager.config.default_binary = binary
    if mcp_port:
        manager.config.mcp_port = mcp_port

    manager.config.save()
    print(f"Configuration saved to {CONFIG_FILE}")
    return manager.config


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manage Ghidra for autonomous workflows")
    parser.add_argument("command", choices=["status", "start", "stop", "restart", "configure"],
                       help="Command to execute")
    parser.add_argument("--project", "-p", help="Ghidra project file (.gpr)")
    parser.add_argument("--binary", "-b", help="Binary to open")
    parser.add_argument("--ghidra-path", help="Path to Ghidra installation")
    parser.add_argument("--force", "-f", action="store_true", help="Force operation")
    parser.add_argument("--no-wait", action="store_true", help="Don't wait for MCP")

    args = parser.parse_args()

    if args.command == "status":
        result = check_ghidra()
        print(f"State: {result['state']}")
        print(f"MCP Available: {result['mcp_available']}")
        print(f"Program Loaded: {result['program_loaded'] or 'None'}")
        if result['recommendations']:
            print("Recommendations:")
            for rec in result['recommendations']:
                print(f"  - {rec}")

    elif args.command == "start":
        success, msg = ensure_ghidra(project=args.project, binary=args.binary)
        print(msg)
        sys.exit(0 if success else 1)

    elif args.command == "stop":
        success = close_ghidra(force=args.force)
        print("Ghidra closed" if success else "Failed to close Ghidra")
        sys.exit(0 if success else 1)

    elif args.command == "restart":
        success, msg = restart_ghidra(
            project=args.project,
            binary=args.binary,
            force=args.force
        )
        print(msg)
        sys.exit(0 if success else 1)

    elif args.command == "configure":
        if not any([args.ghidra_path, args.project, args.binary]):
            print("Current configuration:")
            config = GhidraConfig.load()
            print(f"  Ghidra Path: {config.ghidra_path}")
            print(f"  Default Project: {config.default_project}")
            print(f"  Default Binary: {config.default_binary}")
            print(f"  MCP Port: {config.mcp_port}")
        else:
            config = configure_defaults(
                ghidra_path=args.ghidra_path,
                project=args.project,
                binary=args.binary
            )
            print("Configuration updated")
