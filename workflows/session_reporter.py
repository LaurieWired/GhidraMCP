#!/usr/bin/env python3
"""
Session Reporting for Autonomous Workflow

This module provides comprehensive reporting for autonomous documentation sessions,
including:
- Session summaries with statistics
- Progress tracking over time
- Export to various formats (text, JSON, HTML)
- Historical analysis and trends

Usage:
    from workflows.session_reporter import SessionReporter, generate_report

    reporter = SessionReporter()
    reporter.record_function_documented("ProcessSlots", "0x401000", 0.85, 15)
    report = reporter.generate_summary()
    print(report["text"])
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
import logging

# Setup
LOG_DIR = Path(__file__).parent / "logs"
REPORTS_DIR = Path(__file__).parent / "reports"
STATE_FILE = Path(__file__).parent / ".session_history.json"

LOG_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

logger = logging.getLogger('session_reporter')
logger.setLevel(logging.INFO)


@dataclass
class FunctionRecord:
    """Record of a documented function."""
    original_name: str
    new_name: str
    address: str
    confidence: float
    tokens_used: int
    timestamp: str
    completeness_score: Optional[float] = None
    duration_seconds: Optional[float] = None
    success: bool = True
    error: Optional[str] = None


@dataclass
class SessionRecord:
    """Record of a documentation session."""
    session_id: str
    start_time: str
    end_time: Optional[str] = None
    functions_documented: int = 0
    functions_skipped: int = 0
    functions_failed: int = 0
    total_tokens: int = 0
    ghidra_restarts: int = 0
    recoveries: int = 0
    avg_confidence: float = 0.0
    avg_completeness: float = 0.0
    function_records: List[Dict] = field(default_factory=list)
    status: str = "running"  # running, completed, aborted


@dataclass
class SessionHistory:
    """Persistent history of all sessions."""
    sessions: List[Dict] = field(default_factory=list)
    total_functions_documented: int = 0
    total_tokens_used: int = 0
    total_sessions: int = 0
    first_session: Optional[str] = None
    last_session: Optional[str] = None

    def save(self):
        """Save history to disk."""
        with open(STATE_FILE, 'w') as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> 'SessionHistory':
        """Load history from disk."""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE) as f:
                    data = json.load(f)
                    return cls(**data)
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()


class SessionReporter:
    """
    Comprehensive session reporter for autonomous documentation.

    Tracks progress within sessions and across multiple sessions,
    generates reports in various formats, and maintains historical data.
    """

    def __init__(self, session_id: str = None):
        """
        Initialize the session reporter.

        Args:
            session_id: Unique session ID (auto-generated if not provided)
        """
        self.session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.history = SessionHistory.load()
        self.current_session = SessionRecord(
            session_id=self.session_id,
            start_time=datetime.now().isoformat()
        )
        self._function_start_time: Optional[datetime] = None

        logger.info(f"Session reporter initialized: {self.session_id}")

    def start_function(self, func_name: str, address: str):
        """Mark the start of work on a function."""
        self._function_start_time = datetime.now()
        logger.debug(f"Started work on {func_name} @ {address}")

    def record_function_documented(
        self,
        original_name: str,
        new_name: str,
        address: str,
        confidence: float,
        tokens_used: int,
        completeness_score: float = None,
        success: bool = True,
        error: str = None
    ):
        """
        Record that a function was documented.

        Args:
            original_name: Original function name (e.g., FUN_00401000)
            new_name: New function name (e.g., ProcessSlots)
            address: Function address
            confidence: Analysis confidence (0-1)
            tokens_used: Tokens used for analysis
            completeness_score: Optional completeness score after documentation
            success: Whether documentation was successful
            error: Error message if failed
        """
        duration = None
        if self._function_start_time:
            duration = (datetime.now() - self._function_start_time).total_seconds()
            self._function_start_time = None

        record = FunctionRecord(
            original_name=original_name,
            new_name=new_name,
            address=address,
            confidence=confidence,
            tokens_used=tokens_used,
            timestamp=datetime.now().isoformat(),
            completeness_score=completeness_score,
            duration_seconds=duration,
            success=success,
            error=error
        )

        self.current_session.function_records.append(asdict(record))

        if success:
            self.current_session.functions_documented += 1
        else:
            self.current_session.functions_failed += 1

        self.current_session.total_tokens += tokens_used

        # Update running averages
        n = len(self.current_session.function_records)
        confidences = [r["confidence"] for r in self.current_session.function_records if r["success"]]
        if confidences:
            self.current_session.avg_confidence = sum(confidences) / len(confidences)

        scores = [r["completeness_score"] for r in self.current_session.function_records
                  if r["completeness_score"] is not None]
        if scores:
            self.current_session.avg_completeness = sum(scores) / len(scores)

        logger.info(f"Recorded: {original_name} -> {new_name} (conf={confidence:.2f}, tokens={tokens_used})")

    def record_function_skipped(self, func_name: str, address: str, reason: str):
        """Record that a function was skipped."""
        self.current_session.functions_skipped += 1
        logger.info(f"Skipped: {func_name} @ {address} - {reason}")

    def record_recovery(self, reason: str):
        """Record a recovery event."""
        self.current_session.recoveries += 1
        logger.info(f"Recovery: {reason}")

    def record_ghidra_restart(self):
        """Record a Ghidra restart."""
        self.current_session.ghidra_restarts += 1
        logger.info("Ghidra restart recorded")

    def end_session(self, status: str = "completed"):
        """
        End the current session and save to history.

        Args:
            status: Session end status (completed, aborted, error)
        """
        self.current_session.end_time = datetime.now().isoformat()
        self.current_session.status = status

        # Add to history
        self.history.sessions.append(asdict(self.current_session))
        self.history.total_sessions += 1
        self.history.total_functions_documented += self.current_session.functions_documented
        self.history.total_tokens_used += self.current_session.total_tokens

        if not self.history.first_session:
            self.history.first_session = self.current_session.start_time
        self.history.last_session = self.current_session.end_time

        self.history.save()
        logger.info(f"Session {self.session_id} ended: {status}")

    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate a comprehensive session summary.

        Returns:
            Dict with 'data', 'text', and 'json' keys
        """
        session = self.current_session

        # Calculate duration
        start = datetime.fromisoformat(session.start_time)
        end = datetime.fromisoformat(session.end_time) if session.end_time else datetime.now()
        duration = end - start

        # Build summary data
        data = {
            "session_id": session.session_id,
            "duration": str(duration),
            "duration_seconds": duration.total_seconds(),
            "status": session.status,
            "functions": {
                "documented": session.functions_documented,
                "skipped": session.functions_skipped,
                "failed": session.functions_failed,
                "total_attempted": session.functions_documented + session.functions_skipped + session.functions_failed
            },
            "metrics": {
                "avg_confidence": round(session.avg_confidence, 3),
                "avg_completeness": round(session.avg_completeness, 1),
                "total_tokens": session.total_tokens,
                "tokens_per_function": round(session.total_tokens / max(session.functions_documented, 1), 0)
            },
            "reliability": {
                "recoveries": session.recoveries,
                "ghidra_restarts": session.ghidra_restarts
            },
            "function_records": session.function_records
        }

        # Generate text report
        text_report = self._format_text_report(data)

        return {
            "data": data,
            "text": text_report,
            "json": json.dumps(data, indent=2)
        }

    def _format_text_report(self, data: Dict) -> str:
        """Format a text-based report."""
        lines = [
            "=" * 60,
            f"SESSION REPORT: {data['session_id']}",
            "=" * 60,
            "",
            f"Duration: {data['duration']}",
            f"Status: {data['status'].upper()}",
            "",
            "--- Functions ---",
            f"  Documented: {data['functions']['documented']}",
            f"  Skipped:    {data['functions']['skipped']}",
            f"  Failed:     {data['functions']['failed']}",
            f"  Total:      {data['functions']['total_attempted']}",
            "",
            "--- Metrics ---",
            f"  Avg Confidence:   {data['metrics']['avg_confidence']:.1%}",
            f"  Avg Completeness: {data['metrics']['avg_completeness']:.1f}%",
            f"  Tokens Used:      {data['metrics']['total_tokens']:,}",
            f"  Tokens/Function:  {data['metrics']['tokens_per_function']:.0f}",
            "",
            "--- Reliability ---",
            f"  Recoveries:       {data['reliability']['recoveries']}",
            f"  Ghidra Restarts:  {data['reliability']['ghidra_restarts']}",
            "",
        ]

        # Add function details if present
        if data['function_records']:
            lines.extend([
                "--- Documented Functions ---",
                ""
            ])
            for i, rec in enumerate(data['function_records'][:20], 1):  # Limit to 20
                status = "OK" if rec['success'] else "FAIL"
                lines.append(
                    f"  {i:2}. {rec['original_name']} -> {rec['new_name']} "
                    f"[{status}] conf={rec['confidence']:.0%}"
                )

            if len(data['function_records']) > 20:
                lines.append(f"  ... and {len(data['function_records']) - 20} more")

        lines.extend(["", "=" * 60])

        return "\n".join(lines)

    def generate_history_report(self) -> Dict[str, Any]:
        """
        Generate a report across all historical sessions.

        Returns:
            Dict with historical analysis
        """
        history = self.history

        if not history.sessions:
            return {"message": "No session history available"}

        # Calculate trends
        recent_sessions = history.sessions[-10:]  # Last 10 sessions

        avg_functions = sum(s["functions_documented"] for s in recent_sessions) / len(recent_sessions)
        avg_tokens = sum(s["total_tokens"] for s in recent_sessions) / len(recent_sessions)

        data = {
            "total_sessions": history.total_sessions,
            "total_functions_documented": history.total_functions_documented,
            "total_tokens_used": history.total_tokens_used,
            "first_session": history.first_session,
            "last_session": history.last_session,
            "recent_trends": {
                "avg_functions_per_session": round(avg_functions, 1),
                "avg_tokens_per_session": round(avg_tokens, 0)
            },
            "sessions": [
                {
                    "id": s["session_id"],
                    "date": s["start_time"][:10],
                    "documented": s["functions_documented"],
                    "status": s["status"]
                }
                for s in history.sessions[-20:]
            ]
        }

        return data

    def save_report(self, filename: str = None, format: str = "text") -> str:
        """
        Save the session report to a file.

        Args:
            filename: Output filename (auto-generated if not provided)
            format: Output format (text, json, html)

        Returns:
            Path to saved file
        """
        summary = self.generate_summary()

        if not filename:
            ext = "txt" if format == "text" else format
            filename = f"session_report_{self.session_id}.{ext}"

        filepath = REPORTS_DIR / filename

        if format == "text":
            content = summary["text"]
        elif format == "json":
            content = summary["json"]
        elif format == "html":
            content = self._generate_html_report(summary["data"])
        else:
            content = summary["text"]

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        logger.info(f"Report saved: {filepath}")
        return str(filepath)

    def _generate_html_report(self, data: Dict) -> str:
        """Generate an HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Session Report - {data['session_id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #2196F3; }}
        .metric-label {{ font-size: 12px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f0f0f0; }}
        .success {{ color: green; }}
        .failure {{ color: red; }}
    </style>
</head>
<body>
    <h1>Session Report</h1>
    <p>Session ID: {data['session_id']}</p>
    <p>Duration: {data['duration']} | Status: {data['status'].upper()}</p>

    <div class="section">
        <h2>Summary</h2>
        <div class="metric">
            <div class="metric-value">{data['functions']['documented']}</div>
            <div class="metric-label">Documented</div>
        </div>
        <div class="metric">
            <div class="metric-value">{data['metrics']['avg_confidence']:.0%}</div>
            <div class="metric-label">Avg Confidence</div>
        </div>
        <div class="metric">
            <div class="metric-value">{data['metrics']['total_tokens']:,}</div>
            <div class="metric-label">Tokens Used</div>
        </div>
    </div>

    <div class="section">
        <h2>Functions Documented</h2>
        <table>
            <tr><th>#</th><th>Original</th><th>New Name</th><th>Confidence</th><th>Status</th></tr>
"""
        for i, rec in enumerate(data['function_records'], 1):
            status_class = "success" if rec['success'] else "failure"
            status_text = "OK" if rec['success'] else "FAIL"
            html += f"""            <tr>
                <td>{i}</td>
                <td>{rec['original_name']}</td>
                <td>{rec['new_name']}</td>
                <td>{rec['confidence']:.0%}</td>
                <td class="{status_class}">{status_text}</td>
            </tr>
"""

        html += """        </table>
    </div>
</body>
</html>"""

        return html


# =============================================================================
# Convenience functions
# =============================================================================

def generate_report(session_data: Dict, format: str = "text") -> str:
    """
    Generate a report from session data.

    Args:
        session_data: Dict with session statistics
        format: Output format (text, json)

    Returns:
        Formatted report string
    """
    reporter = SessionReporter()

    # Populate from session data
    if "function_records" in session_data:
        for rec in session_data["function_records"]:
            reporter.record_function_documented(**rec)

    summary = reporter.generate_summary()
    return summary.get(format, summary["text"])


def get_history_summary() -> Dict[str, Any]:
    """Get a summary of historical sessions."""
    reporter = SessionReporter()
    return reporter.generate_history_report()


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Session Reporter")
    parser.add_argument("--history", action="store_true", help="Show session history")
    parser.add_argument("--last", action="store_true", help="Show last session report")
    parser.add_argument("--export", choices=["text", "json", "html"], help="Export format")

    args = parser.parse_args()

    if args.history:
        history = SessionHistory.load()
        print(json.dumps({
            "total_sessions": history.total_sessions,
            "total_functions": history.total_functions_documented,
            "total_tokens": history.total_tokens_used,
            "first": history.first_session,
            "last": history.last_session
        }, indent=2))
        return 0

    if args.last:
        history = SessionHistory.load()
        if history.sessions:
            last = history.sessions[-1]
            reporter = SessionReporter(last["session_id"])
            reporter.current_session = SessionRecord(**last)
            summary = reporter.generate_summary()
            print(summary["text"])
        else:
            print("No session history available")
        return 0

    # Default: show usage
    parser.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
