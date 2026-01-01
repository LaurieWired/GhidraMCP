#!/usr/bin/env python3
"""
Bookmark-Based Progress Tracking for Ghidra Documentation

This module uses Ghidra's native bookmark system to track documentation progress
directly in the binary. This allows progress to travel with the .gzf file.

Bookmark Schema:
    Category: "RE_PROGRESS"
    Address: Function entry point
    Comment: "score:85|issues:2|last:2025-11-26|status:documented"

Benefits:
    - Progress travels with the binary file
    - Visible in Ghidra's Bookmark window
    - Queryable via MCP tools
    - Survives workflow restarts

Usage:
    from workflows.bookmark_tracker import BookmarkProgressTracker

    tracker = BookmarkProgressTracker(ghidra_client)
    tracker.set_function_progress("0x401000", score=85, issues=2)
    progress = tracker.get_function_progress("0x401000")
    summary = tracker.get_overall_progress()
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
import logging

logger = logging.getLogger('bookmark_tracker')
logger.setLevel(logging.INFO)

# Bookmark category for our progress tracking
PROGRESS_CATEGORY = "RE_PROGRESS"

# Status values
STATUS_UNDOCUMENTED = "undocumented"
STATUS_IN_PROGRESS = "in_progress"
STATUS_DOCUMENTED = "documented"
STATUS_NEEDS_WORK = "needs_work"
STATUS_COMPLETE = "complete"  # 90%+ score


@dataclass
class FunctionProgress:
    """Progress data for a single function."""
    address: str
    name: Optional[str] = None
    score: float = 0.0
    issues: int = 0
    last_updated: str = ""
    status: str = STATUS_UNDOCUMENTED

    def to_bookmark_comment(self) -> str:
        """Encode progress as bookmark comment string."""
        # Format: score:XX|issues:X|last:YYYY-MM-DD|status:STATUS
        date_str = self.last_updated[:10] if self.last_updated else datetime.now().strftime("%Y-%m-%d")
        return f"score:{self.score:.0f}|issues:{self.issues}|last:{date_str}|status:{self.status}"

    @classmethod
    def from_bookmark_comment(cls, address: str, comment: str) -> 'FunctionProgress':
        """Decode progress from bookmark comment string."""
        progress = cls(address=address)

        if not comment:
            return progress

        # Parse the pipe-delimited format
        parts = comment.split("|")
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "score":
                    try:
                        progress.score = float(value)
                    except ValueError:
                        pass
                elif key == "issues":
                    try:
                        progress.issues = int(value)
                    except ValueError:
                        pass
                elif key == "last":
                    progress.last_updated = value
                elif key == "status":
                    progress.status = value

        return progress


class BookmarkProgressTracker:
    """
    Track documentation progress using Ghidra bookmarks.

    This provides per-function progress tracking that travels with the binary,
    complementing the JSON-based session/workflow metrics.
    """

    def __init__(self, ghidra_client):
        """
        Initialize the tracker.

        Args:
            ghidra_client: Client with call() method for MCP communication
        """
        self.client = ghidra_client
        self._cache: Dict[str, FunctionProgress] = {}
        self._cache_valid = False

    def _call_ghidra(self, endpoint: str, params: Dict = None, method: str = "GET") -> Dict[str, Any]:
        """Make a call to Ghidra MCP."""
        try:
            result = self.client.call(endpoint, params, method)
            return result if isinstance(result, dict) else {"success": False, "error": "Invalid response"}
        except Exception as e:
            logger.error(f"Ghidra call failed: {endpoint} - {e}")
            return {"success": False, "error": str(e)}

    def set_function_progress(
        self,
        address: str,
        score: float,
        issues: int = 0,
        status: str = None,
        name: str = None
    ) -> bool:
        """
        Set the progress for a function using a Ghidra bookmark.

        Args:
            address: Function address (hex string)
            score: Completeness score (0-100)
            issues: Number of open issues
            status: Optional status override (auto-calculated if not provided)
            name: Optional function name for reference

        Returns:
            True if bookmark was set successfully
        """
        # Auto-calculate status if not provided
        if status is None:
            if score >= 90:
                status = STATUS_COMPLETE
            elif score >= 70:
                status = STATUS_DOCUMENTED
            elif score > 0:
                status = STATUS_NEEDS_WORK
            else:
                status = STATUS_UNDOCUMENTED

        progress = FunctionProgress(
            address=address,
            name=name,
            score=score,
            issues=issues,
            last_updated=datetime.now().isoformat(),
            status=status
        )

        # Create the bookmark
        comment = progress.to_bookmark_comment()
        result = self._call_ghidra("set_bookmark", {
            "address": address,
            "category": PROGRESS_CATEGORY,
            "comment": comment
        }, method="POST")

        if result.get("success"):
            self._cache[address] = progress
            logger.info(f"Set progress bookmark: {address} -> score={score}, status={status}")
            return True
        else:
            logger.error(f"Failed to set bookmark for {address}: {result.get('error')}")
            return False

    def get_function_progress(self, address: str) -> Optional[FunctionProgress]:
        """
        Get the progress for a specific function.

        Args:
            address: Function address (hex string)

        Returns:
            FunctionProgress or None if no bookmark exists
        """
        # Check cache first
        if address in self._cache:
            return self._cache[address]

        # Query Ghidra for bookmarks at this address
        result = self._call_ghidra("list_bookmarks", {
            "category": PROGRESS_CATEGORY,
            "address": address
        })

        if result.get("success") and result.get("data"):
            try:
                data = json.loads(result["data"]) if isinstance(result["data"], str) else result["data"]
                bookmarks = data if isinstance(data, list) else data.get("bookmarks", [])

                for bm in bookmarks:
                    if bm.get("address", "").lower() == address.lower():
                        progress = FunctionProgress.from_bookmark_comment(
                            address,
                            bm.get("comment", "")
                        )
                        self._cache[address] = progress
                        return progress
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Failed to parse bookmark data: {e}")

        return None

    def get_all_progress(self, force_refresh: bool = False) -> Dict[str, FunctionProgress]:
        """
        Get progress for all tracked functions.

        Args:
            force_refresh: Force re-fetch from Ghidra even if cached

        Returns:
            Dict mapping address to FunctionProgress
        """
        if self._cache_valid and not force_refresh:
            return self._cache

        # Fetch all progress bookmarks
        result = self._call_ghidra("list_bookmarks", {
            "category": PROGRESS_CATEGORY
        })

        progress_map = {}

        if result.get("success") and result.get("data"):
            try:
                data = json.loads(result["data"]) if isinstance(result["data"], str) else result["data"]
                bookmarks = data if isinstance(data, list) else data.get("bookmarks", [])

                for bm in bookmarks:
                    address = bm.get("address", "")
                    if address:
                        progress = FunctionProgress.from_bookmark_comment(
                            address,
                            bm.get("comment", "")
                        )
                        progress_map[address] = progress

                self._cache = progress_map
                self._cache_valid = True
                logger.info(f"Loaded {len(progress_map)} progress bookmarks from Ghidra")

            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Failed to parse bookmarks: {e}")

        return progress_map

    def get_overall_progress(self) -> Dict[str, Any]:
        """
        Calculate overall documentation progress from bookmarks.

        Returns:
            Dict with:
            - total_tracked: Number of functions with progress bookmarks
            - avg_score: Average completeness score
            - by_status: Count per status
            - needs_work: List of addresses needing work
            - complete: List of addresses that are complete
        """
        all_progress = self.get_all_progress()

        if not all_progress:
            return {
                "total_tracked": 0,
                "avg_score": 0.0,
                "by_status": {},
                "needs_work": [],
                "complete": []
            }

        total_score = 0
        by_status = {}
        needs_work = []
        complete = []

        for address, progress in all_progress.items():
            total_score += progress.score

            status = progress.status
            by_status[status] = by_status.get(status, 0) + 1

            if progress.score < 70 or progress.issues > 0:
                needs_work.append({
                    "address": address,
                    "score": progress.score,
                    "issues": progress.issues,
                    "status": status
                })
            elif progress.score >= 90:
                complete.append({
                    "address": address,
                    "score": progress.score
                })

        # Sort needs_work by score ascending (worst first)
        needs_work.sort(key=lambda x: x["score"])

        return {
            "total_tracked": len(all_progress),
            "avg_score": total_score / len(all_progress),
            "by_status": by_status,
            "needs_work": needs_work[:20],  # Limit to top 20
            "complete": complete
        }

    def mark_function_in_progress(self, address: str, name: str = None) -> bool:
        """Mark a function as currently being worked on."""
        return self.set_function_progress(
            address=address,
            score=0,
            issues=0,
            status=STATUS_IN_PROGRESS,
            name=name
        )

    def update_from_completeness(self, address: str, completeness_data: Dict) -> bool:
        """
        Update progress from analyze_function_completeness result.

        Args:
            address: Function address
            completeness_data: Result from analyze_function_completeness

        Returns:
            True if bookmark was updated
        """
        score = completeness_data.get("completeness_score", 0)

        # Count issues from various sources
        issues = 0
        issues += len(completeness_data.get("undefined_variables", []))
        issues += len(completeness_data.get("hungarian_notation_violations", []))
        issues += len(completeness_data.get("recommendations", []))
        issues += len(completeness_data.get("plate_comment_issues", []))

        name = completeness_data.get("function_name")

        return self.set_function_progress(
            address=address,
            score=score,
            issues=issues,
            name=name
        )

    def clear_progress(self, address: str) -> bool:
        """
        Remove the progress bookmark for a function.

        Args:
            address: Function address

        Returns:
            True if bookmark was removed
        """
        result = self._call_ghidra("delete_bookmark", {
            "address": address,
            "category": PROGRESS_CATEGORY
        }, method="POST")

        if result.get("success"):
            if address in self._cache:
                del self._cache[address]
            return True
        return False

    def invalidate_cache(self):
        """Invalidate the internal cache, forcing refresh on next query."""
        self._cache_valid = False
        self._cache = {}


class ProgressSynchronizer:
    """
    Synchronize progress between Ghidra bookmarks and JSON state files.

    This ensures both systems stay in sync:
    - Bookmarks: Per-function progress (travels with binary)
    - JSON: Session metrics, tool health, trends (workflow metadata)
    """

    def __init__(self, bookmark_tracker: BookmarkProgressTracker, quality_history_path: Path = None):
        """
        Initialize the synchronizer.

        Args:
            bookmark_tracker: BookmarkProgressTracker instance
            quality_history_path: Path to .quality_history.json
        """
        self.bookmarks = bookmark_tracker
        self.quality_path = quality_history_path or Path(__file__).parent / ".quality_history.json"

    def sync_bookmarks_to_json(self) -> Dict[str, Any]:
        """
        Export bookmark progress to JSON quality history.

        This updates the JSON file with current bookmark data,
        useful for generating reports and trends.

        Returns:
            Sync statistics
        """
        all_progress = self.bookmarks.get_all_progress(force_refresh=True)

        # Load existing quality history
        quality_history = {"records": {}, "summary": {}}
        if self.quality_path.exists():
            try:
                with open(self.quality_path) as f:
                    quality_history = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        synced = 0
        for address, progress in all_progress.items():
            # Add/update record in quality history
            if address not in quality_history["records"]:
                quality_history["records"][address] = []

            # Add new entry if score changed or first entry
            existing = quality_history["records"][address]
            if not existing or existing[-1].get("completeness_score") != progress.score:
                quality_history["records"][address].append({
                    "address": address,
                    "name": progress.name or address,
                    "timestamp": progress.last_updated or datetime.now().isoformat(),
                    "completeness_score": progress.score,
                    "recommendations": [],  # Not available from bookmark
                    "source": "bookmark_sync"
                })
                synced += 1

        # Update summary
        if all_progress:
            scores = [p.score for p in all_progress.values()]
            quality_history["summary"] = {
                "last_scan": datetime.now().isoformat(),
                "functions_scanned": len(all_progress),
                "avg_score": sum(scores) / len(scores),
                "needs_work_count": sum(1 for p in all_progress.values() if p.score < 70),
                "well_documented_count": sum(1 for p in all_progress.values() if p.score >= 90),
                "source": "bookmark_sync"
            }

        # Save
        with open(self.quality_path, 'w') as f:
            json.dump(quality_history, f, indent=2)

        logger.info(f"Synced {synced} bookmark records to JSON")
        return {"synced_records": synced, "total_functions": len(all_progress)}

    def sync_json_to_bookmarks(self) -> Dict[str, Any]:
        """
        Import JSON quality history to bookmarks.

        Useful when loading a binary that doesn't have bookmarks
        but we have historical data from previous sessions.

        Returns:
            Sync statistics
        """
        if not self.quality_path.exists():
            return {"synced_records": 0, "error": "No quality history file"}

        try:
            with open(self.quality_path) as f:
                quality_history = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            return {"synced_records": 0, "error": str(e)}

        synced = 0
        failed = 0

        for address, records in quality_history.get("records", {}).items():
            if records:
                latest = records[-1]
                score = latest.get("completeness_score", 0)
                issues = len(latest.get("recommendations", []))

                # Check if bookmark already exists with same/higher score
                existing = self.bookmarks.get_function_progress(address)
                if existing and existing.score >= score:
                    continue  # Don't overwrite with older data

                if self.bookmarks.set_function_progress(
                    address=address,
                    score=score,
                    issues=issues,
                    name=latest.get("name")
                ):
                    synced += 1
                else:
                    failed += 1

        logger.info(f"Synced {synced} records from JSON to bookmarks ({failed} failed)")
        return {"synced_records": synced, "failed": failed}


# =============================================================================
# Convenience functions
# =============================================================================

def create_tracker(ghidra_client) -> BookmarkProgressTracker:
    """Create a bookmark progress tracker."""
    return BookmarkProgressTracker(ghidra_client)


def get_progress_summary(ghidra_client) -> Dict[str, Any]:
    """Quick function to get overall progress from bookmarks."""
    tracker = BookmarkProgressTracker(ghidra_client)
    return tracker.get_overall_progress()


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI entry point for testing."""
    import argparse
    import sys

    # Add parent to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    parser = argparse.ArgumentParser(description="Bookmark Progress Tracker")
    parser.add_argument("--summary", action="store_true", help="Show progress summary")
    parser.add_argument("--sync-to-json", action="store_true", help="Sync bookmarks to JSON")
    parser.add_argument("--sync-from-json", action="store_true", help="Sync JSON to bookmarks")
    parser.add_argument("--list", action="store_true", help="List all progress bookmarks")

    args = parser.parse_args()

    # Create a minimal Ghidra client
    class GhidraClient:
        def __init__(self):
            import requests
            self.server = "http://127.0.0.1:8089"
            self.requests = requests

        def call(self, endpoint, params=None, method="GET", timeout=30):
            try:
                url = f"{self.server}/{endpoint}"
                if method == "GET":
                    r = self.requests.get(url, params=params, timeout=timeout)
                else:
                    r = self.requests.post(url, json=params, timeout=timeout)
                return {"success": r.status_code == 200, "data": r.text}
            except Exception as e:
                return {"success": False, "error": str(e)}

    client = GhidraClient()
    tracker = BookmarkProgressTracker(client)

    if args.summary:
        summary = tracker.get_overall_progress()
        print(json.dumps(summary, indent=2))
        return 0

    if args.list:
        all_progress = tracker.get_all_progress()
        for addr, prog in sorted(all_progress.items()):
            print(f"{addr}: score={prog.score:.0f}%, issues={prog.issues}, status={prog.status}")
        print(f"\nTotal: {len(all_progress)} functions tracked")
        return 0

    if args.sync_to_json:
        sync = ProgressSynchronizer(tracker)
        result = sync.sync_bookmarks_to_json()
        print(json.dumps(result, indent=2))
        return 0

    if args.sync_from_json:
        sync = ProgressSynchronizer(tracker)
        result = sync.sync_json_to_bookmarks()
        print(json.dumps(result, indent=2))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
