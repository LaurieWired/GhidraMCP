#!/usr/bin/env python3
"""
Progress Dashboard for Autonomous Documentation Workflow

This module provides a command-line dashboard for monitoring:
- Overall documentation progress
- Session statistics
- Quality metrics
- Ghidra connection status
- Recent activity

Usage:
    python dashboard.py                    # Show full dashboard
    python dashboard.py --quick            # Quick status only
    python dashboard.py --json             # JSON output
    python dashboard.py --watch            # Auto-refresh mode
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from workflows.session_reporter import SessionHistory
from workflows.quality_tracker import QualityHistory


# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.HEADER = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.RESET = ''


def check_ghidra_status() -> Dict[str, Any]:
    """Check Ghidra/MCP connection status."""
    try:
        import requests
        response = requests.get("http://127.0.0.1:8089/methods", timeout=2)
        if response.status_code == 200:
            return {"status": "connected", "program": "unknown"}
    except Exception:
        pass

    # Try to get more info
    try:
        import requests
        response = requests.get("http://127.0.0.1:8089/get_metadata", timeout=2)
        if response.status_code == 200:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            return {
                "status": "connected",
                "program": data.get("programName", "unknown")
            }
    except Exception:
        pass

    return {"status": "disconnected", "program": None}


def load_improvement_state() -> Dict[str, Any]:
    """Load the improvement state file."""
    state_file = Path(__file__).parent / ".improvement_state.json"
    if state_file.exists():
        try:
            with open(state_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def load_self_improvement_state() -> Dict[str, Any]:
    """Load the self-improvement state file (issues, tool health)."""
    state_file = Path(__file__).parent / ".self_improvement_state.json"
    if state_file.exists():
        try:
            with open(state_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def load_bookmark_progress() -> Dict[str, Any]:
    """Load progress from Ghidra bookmarks (if connected)."""
    try:
        # Try to import and use the bookmark tracker
        try:
            from workflows.bookmark_tracker import BookmarkProgressTracker
        except ImportError:
            from bookmark_tracker import BookmarkProgressTracker

        # Create minimal client for querying
        import requests

        class GhidraClient:
            def __init__(self):
                self.server = "http://127.0.0.1:8089"

            def call(self, endpoint, params=None, method="GET", timeout=5):
                try:
                    url = f"{self.server}/{endpoint}"
                    if method == "GET":
                        r = requests.get(url, params=params, timeout=timeout)
                    else:
                        r = requests.post(url, json=params, timeout=timeout)
                    return {"success": r.status_code == 200, "data": r.text}
                except Exception as e:
                    return {"success": False, "error": str(e)}

        client = GhidraClient()
        tracker = BookmarkProgressTracker(client)
        return tracker.get_overall_progress()

    except Exception as e:
        return {"error": str(e), "total_tracked": 0}


def format_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp as relative time."""
    if not iso_timestamp:
        return "never"
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        delta = now - dt

        if delta.total_seconds() < 60:
            return "just now"
        elif delta.total_seconds() < 3600:
            return f"{int(delta.total_seconds() / 60)}m ago"
        elif delta.total_seconds() < 86400:
            return f"{int(delta.total_seconds() / 3600)}h ago"
        else:
            return f"{int(delta.days)}d ago"
    except (ValueError, TypeError):
        return iso_timestamp[:10] if iso_timestamp else "unknown"


def generate_progress_bar(value: float, max_value: float, width: int = 30) -> str:
    """Generate a text-based progress bar."""
    if max_value <= 0:
        return "[" + " " * width + "]"

    ratio = min(value / max_value, 1.0)
    filled = int(width * ratio)
    empty = width - filled

    bar = "[" + "=" * filled + " " * empty + "]"
    return bar


def generate_dashboard() -> str:
    """Generate the full dashboard display."""
    lines = []
    c = Colors

    # Header
    lines.append("")
    lines.append(f"{c.BOLD}{c.CYAN}{'=' * 60}{c.RESET}")
    lines.append(f"{c.BOLD}{c.CYAN}  GHIDRA MCP AUTONOMOUS WORKFLOW DASHBOARD{c.RESET}")
    lines.append(f"{c.BOLD}{c.CYAN}{'=' * 60}{c.RESET}")
    lines.append(f"{c.DIM}  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{c.RESET}")
    lines.append("")

    # Connection Status
    ghidra = check_ghidra_status()
    if ghidra["status"] == "connected":
        status_color = c.GREEN
        status_icon = "[OK]"
    else:
        status_color = c.RED
        status_icon = "[X]"

    lines.append(f"{c.BOLD}CONNECTION STATUS{c.RESET}")
    lines.append(f"  Ghidra MCP: {status_color}{status_icon} {ghidra['status'].upper()}{c.RESET}")
    if ghidra.get("program"):
        lines.append(f"  Program:    {ghidra['program']}")
    lines.append("")

    # Load state data
    state = load_improvement_state()
    session_history = SessionHistory.load()
    quality_history = QualityHistory.load()

    # Overall Progress
    lines.append(f"{c.BOLD}OVERALL PROGRESS{c.RESET}")

    total_documented = state.get("functions_documented", 0)
    lines.append(f"  Functions Documented: {c.GREEN}{total_documented}{c.RESET}")

    total_sessions = session_history.total_sessions
    lines.append(f"  Sessions Run:         {total_sessions}")

    total_tokens = session_history.total_tokens_used
    lines.append(f"  Total Tokens Used:    {total_tokens:,}")

    # Calculate estimated cost (rough estimate)
    est_cost = (total_tokens / 1_000_000) * 10  # ~$10/MTok average
    lines.append(f"  Estimated API Cost:   ${est_cost:.2f}")
    lines.append("")

    # Session Statistics
    lines.append(f"{c.BOLD}SESSION STATISTICS{c.RESET}")

    if session_history.sessions:
        last_session = session_history.sessions[-1]
        lines.append(f"  Last Session:    {format_timestamp(last_session.get('end_time', last_session.get('start_time')))}")
        lines.append(f"  Last Status:     {last_session.get('status', 'unknown').upper()}")
        lines.append(f"  Last Documented: {last_session.get('functions_documented', 0)} functions")

        # Calculate averages from recent sessions
        recent = session_history.sessions[-10:]
        avg_funcs = sum(s.get("functions_documented", 0) for s in recent) / len(recent)
        avg_tokens = sum(s.get("total_tokens", 0) for s in recent) / len(recent)
        lines.append(f"  Avg per Session: {avg_funcs:.1f} functions, {avg_tokens:.0f} tokens")
    else:
        lines.append(f"  {c.DIM}No sessions recorded yet{c.RESET}")
    lines.append("")

    # Quality Metrics
    lines.append(f"{c.BOLD}QUALITY METRICS{c.RESET}")

    if quality_history.summary:
        summary = quality_history.summary
        avg_score = summary.get("avg_score", 0)

        # Color-code the score
        if avg_score >= 80:
            score_color = c.GREEN
        elif avg_score >= 60:
            score_color = c.YELLOW
        else:
            score_color = c.RED

        bar = generate_progress_bar(avg_score, 100, 20)
        lines.append(f"  Avg Completeness: {score_color}{avg_score:.1f}%{c.RESET} {bar}")
        lines.append(f"  Functions Tracked: {summary.get('functions_scanned', 0)}")
        lines.append(f"  Need Work (<70%):  {summary.get('needs_work_count', 0)}")
        lines.append(f"  Well Doc'd (90%+): {summary.get('well_documented_count', 0)}")
        lines.append(f"  Last Scan:         {format_timestamp(summary.get('last_scan'))}")
    else:
        lines.append(f"  {c.DIM}No quality data available - run a quality scan{c.RESET}")
    lines.append("")

    # Bookmark Progress (from Ghidra)
    if ghidra["status"] == "connected":
        lines.append(f"{c.BOLD}BOOKMARK PROGRESS (in-binary){c.RESET}")
        bookmark_progress = load_bookmark_progress()

        if bookmark_progress.get("total_tracked", 0) > 0:
            bm_avg = bookmark_progress.get("avg_score", 0)
            bm_total = bookmark_progress.get("total_tracked", 0)

            # Color-code the bookmark score
            if bm_avg >= 80:
                bm_color = c.GREEN
            elif bm_avg >= 60:
                bm_color = c.YELLOW
            else:
                bm_color = c.RED

            bm_bar = generate_progress_bar(bm_avg, 100, 20)
            lines.append(f"  Avg Score:       {bm_color}{bm_avg:.1f}%{c.RESET} {bm_bar}")
            lines.append(f"  Tracked Funcs:   {bm_total}")

            by_status = bookmark_progress.get("by_status", {})
            if by_status:
                status_parts = []
                for status, count in by_status.items():
                    status_parts.append(f"{status}:{count}")
                lines.append(f"  By Status:       {', '.join(status_parts)}")

            needs_work = bookmark_progress.get("needs_work", [])
            if needs_work:
                lines.append(f"  {c.YELLOW}Need Work:{c.RESET}        {len(needs_work)} functions")
        elif "error" in bookmark_progress:
            lines.append(f"  {c.DIM}Error: {bookmark_progress['error'][:40]}{c.RESET}")
        else:
            lines.append(f"  {c.DIM}No progress bookmarks yet{c.RESET}")
        lines.append("")

    # Current State
    lines.append(f"{c.BOLD}CURRENT STATE{c.RESET}")

    current_func = state.get("current_function")
    if current_func:
        lines.append(f"  Working On:     {c.YELLOW}{current_func}{c.RESET}")
        lines.append(f"  At Address:     {state.get('current_function_address', 'unknown')}")
    else:
        lines.append(f"  Working On:     {c.DIM}(idle){c.RESET}")

    lines.append(f"  Recoveries:     {state.get('recovery_count', 0)}")
    lines.append(f"  Ghidra Restarts: {state.get('ghidra_restarts', 0)}")
    lines.append(f"  Last Checkpoint: {format_timestamp(state.get('last_checkpoint'))}")
    lines.append("")

    # Recent Activity (last 5 documented)
    lines.append(f"{c.BOLD}RECENT ACTIVITY{c.RESET}")

    documented_addrs = state.get("documented_addresses", [])
    if documented_addrs:
        recent_addrs = documented_addrs[-5:]
        for i, addr in enumerate(reversed(recent_addrs), 1):
            lines.append(f"  {i}. {addr}")
    else:
        lines.append(f"  {c.DIM}No functions documented yet{c.RESET}")
    lines.append("")

    # Pending Changes (tool improvements)
    pending = state.get("pending_changes", [])
    if pending:
        lines.append(f"{c.BOLD}PENDING TOOL CHANGES{c.RESET}")
        for change in pending[:3]:
            status = change.get("status", "proposed")
            desc = change.get("description", "unknown")[:40]
            lines.append(f"  [{status}] {desc}")
        if len(pending) > 3:
            lines.append(f"  ... and {len(pending) - 3} more")
        lines.append("")

    # Footer
    lines.append(f"{c.CYAN}{'=' * 60}{c.RESET}")
    lines.append("")

    return "\n".join(lines)


def generate_quick_status() -> str:
    """Generate a quick one-line status."""
    ghidra = check_ghidra_status()
    state = load_improvement_state()
    session_history = SessionHistory.load()

    ghidra_status = "OK" if ghidra["status"] == "connected" else "DISCONNECTED"
    docs = state.get("functions_documented", 0)
    sessions = session_history.total_sessions
    current = state.get("current_function", "idle")

    return f"Ghidra: {ghidra_status} | Documented: {docs} | Sessions: {sessions} | Current: {current}"


def generate_json_output() -> str:
    """Generate JSON output for programmatic use."""
    ghidra = check_ghidra_status()
    state = load_improvement_state()
    session_history = SessionHistory.load()
    quality_history = QualityHistory.load()

    output = {
        "timestamp": datetime.now().isoformat(),
        "connection": ghidra,
        "progress": {
            "functions_documented": state.get("functions_documented", 0),
            "sessions_run": session_history.total_sessions,
            "total_tokens": session_history.total_tokens_used
        },
        "current_state": {
            "current_function": state.get("current_function"),
            "current_address": state.get("current_function_address"),
            "recoveries": state.get("recovery_count", 0),
            "ghidra_restarts": state.get("ghidra_restarts", 0),
            "last_checkpoint": state.get("last_checkpoint")
        },
        "quality": quality_history.summary,
        "recent_sessions": [
            {
                "id": s.get("session_id"),
                "documented": s.get("functions_documented", 0),
                "status": s.get("status")
            }
            for s in session_history.sessions[-5:]
        ]
    }

    return json.dumps(output, indent=2)


def watch_mode(interval: int = 5):
    """Run dashboard in watch mode with auto-refresh."""
    try:
        while True:
            # Clear screen
            os.system('cls' if os.name == 'nt' else 'clear')

            # Generate and print dashboard
            print(generate_dashboard())
            print(f"Auto-refreshing every {interval}s. Press Ctrl+C to exit.")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nExiting watch mode.")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Progress Dashboard for Autonomous Documentation Workflow"
    )
    parser.add_argument("--quick", "-q", action="store_true",
                       help="Quick one-line status")
    parser.add_argument("--json", "-j", action="store_true",
                       help="JSON output")
    parser.add_argument("--watch", "-w", action="store_true",
                       help="Auto-refresh mode")
    parser.add_argument("--interval", "-i", type=int, default=5,
                       help="Refresh interval for watch mode (default: 5s)")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable color output")

    args = parser.parse_args()

    # Disable colors if requested or not a TTY
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    if args.quick:
        print(generate_quick_status())
        return 0

    if args.json:
        print(generate_json_output())
        return 0

    if args.watch:
        watch_mode(args.interval)
        return 0

    # Default: full dashboard
    print(generate_dashboard())
    return 0


if __name__ == "__main__":
    sys.exit(main())
