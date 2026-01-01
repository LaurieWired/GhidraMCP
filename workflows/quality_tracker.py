#!/usr/bin/env python3
"""
Quality Tracking for Documentation Progress

This module integrates with Ghidra's analyze_function_completeness tool to:
- Track completeness scores over time
- Monitor documentation quality trends
- Identify areas needing improvement
- Generate quality reports

Usage:
    from workflows.quality_tracker import QualityTracker

    tracker = QualityTracker(loop)
    score = tracker.check_function_quality("0x401000")
    report = tracker.generate_quality_report()
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import logging

# Setup
STATE_FILE = Path(__file__).parent / ".quality_history.json"
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger('quality_tracker')
logger.setLevel(logging.INFO)


@dataclass
class QualityRecord:
    """Record of a function's quality assessment."""
    address: str
    name: str
    timestamp: str
    completeness_score: float
    has_custom_name: bool = False
    has_prototype: bool = False
    has_calling_convention: bool = False
    has_plate_comment: bool = False
    plate_comment_issues: List[str] = field(default_factory=list)
    undefined_variables: List[str] = field(default_factory=list)
    hungarian_violations: List[str] = field(default_factory=list)
    type_quality_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class QualityHistory:
    """Persistent quality tracking history."""
    records: Dict[str, List[Dict]] = field(default_factory=dict)  # address -> list of records
    summary: Dict[str, Any] = field(default_factory=dict)
    last_updated: Optional[str] = None

    def save(self):
        """Save to disk."""
        with open(STATE_FILE, 'w') as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> 'QualityHistory':
        """Load from disk."""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE) as f:
                    data = json.load(f)
                    return cls(**data)
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()


class QualityTracker:
    """
    Quality tracking system for documentation completeness.

    Integrates with Ghidra's analyze_function_completeness endpoint
    to track and trend documentation quality over time.
    """

    def __init__(self, improvement_loop):
        """
        Initialize the quality tracker.

        Args:
            improvement_loop: ContinuousImprovementLoop instance for Ghidra calls
        """
        self.loop = improvement_loop
        self.history = QualityHistory.load()

    def check_function_quality(self, func_address: str, func_name: str = None) -> QualityRecord:
        """
        Check the documentation quality of a function.

        Args:
            func_address: Function address (hex string)
            func_name: Optional function name (for logging)

        Returns:
            QualityRecord with completeness analysis
        """
        result = self.loop.call_with_recovery(
            "analyze_function_completeness",
            {"function_address": func_address}
        )

        record = QualityRecord(
            address=func_address,
            name=func_name or func_address,
            timestamp=datetime.now().isoformat(),
            completeness_score=0.0
        )

        if result.get("success") and result.get("data"):
            try:
                data = json.loads(result["data"])

                record.completeness_score = data.get("completeness_score", 0.0)
                record.has_custom_name = data.get("has_custom_name", False)
                record.has_prototype = data.get("has_prototype", False)
                record.has_calling_convention = data.get("has_calling_convention", False)
                record.has_plate_comment = data.get("has_plate_comment", False)
                record.plate_comment_issues = data.get("plate_comment_issues", [])
                record.undefined_variables = data.get("undefined_variables", [])
                record.hungarian_violations = data.get("hungarian_notation_violations", [])
                record.type_quality_issues = data.get("type_quality_issues", [])
                record.recommendations = data.get("recommendations", [])

            except json.JSONDecodeError:
                logger.warning(f"Could not parse completeness data for {func_address}")

        # Store in history
        if func_address not in self.history.records:
            self.history.records[func_address] = []
        self.history.records[func_address].append(asdict(record))
        self.history.last_updated = datetime.now().isoformat()
        self.history.save()

        logger.info(f"Quality check: {func_name or func_address} = {record.completeness_score}%")
        return record

    def get_function_trend(self, func_address: str) -> Dict[str, Any]:
        """
        Get the quality trend for a specific function.

        Args:
            func_address: Function address

        Returns:
            Dict with trend data:
            - current_score: Latest completeness score
            - previous_score: Previous completeness score (if available)
            - improvement: Score change
            - records_count: Number of historical records
            - history: List of (timestamp, score) tuples
        """
        records = self.history.records.get(func_address, [])

        if not records:
            return {"error": "No history for this function"}

        current = records[-1]
        previous = records[-2] if len(records) > 1 else None

        return {
            "current_score": current["completeness_score"],
            "previous_score": previous["completeness_score"] if previous else None,
            "improvement": (current["completeness_score"] - previous["completeness_score"])
                          if previous else 0,
            "records_count": len(records),
            "history": [(r["timestamp"], r["completeness_score"]) for r in records]
        }

    def scan_functions(
        self,
        functions: List[Dict],
        progress_callback: callable = None
    ) -> Dict[str, Any]:
        """
        Scan multiple functions and assess quality.

        Args:
            functions: List of dicts with 'name' and 'address'
            progress_callback: Optional callback(current, total, record)

        Returns:
            Dict with scan results:
            - total: Functions scanned
            - avg_score: Average completeness score
            - score_distribution: Dict of score ranges
            - needs_work: Functions scoring below 70%
            - well_documented: Functions scoring 90%+
        """
        results = {
            "total": len(functions),
            "scanned": 0,
            "avg_score": 0.0,
            "score_distribution": {
                "0-25": 0,
                "25-50": 0,
                "50-75": 0,
                "75-90": 0,
                "90-100": 0
            },
            "needs_work": [],
            "well_documented": [],
            "records": []
        }

        total_score = 0

        for i, func in enumerate(functions):
            record = self.check_function_quality(func["address"], func.get("name"))
            results["records"].append(asdict(record))
            results["scanned"] += 1

            score = record.completeness_score
            total_score += score

            # Categorize
            if score < 25:
                results["score_distribution"]["0-25"] += 1
            elif score < 50:
                results["score_distribution"]["25-50"] += 1
            elif score < 75:
                results["score_distribution"]["50-75"] += 1
            elif score < 90:
                results["score_distribution"]["75-90"] += 1
            else:
                results["score_distribution"]["90-100"] += 1

            if score < 70:
                results["needs_work"].append({
                    "name": func.get("name", record.name),
                    "address": func["address"],
                    "score": score,
                    "issues": len(record.recommendations)
                })
            elif score >= 90:
                results["well_documented"].append({
                    "name": func.get("name", record.name),
                    "address": func["address"],
                    "score": score
                })

            if progress_callback:
                progress_callback(i + 1, len(functions), record)

        results["avg_score"] = total_score / max(results["scanned"], 1)

        # Update summary
        self.history.summary = {
            "last_scan": datetime.now().isoformat(),
            "functions_scanned": results["scanned"],
            "avg_score": results["avg_score"],
            "needs_work_count": len(results["needs_work"]),
            "well_documented_count": len(results["well_documented"])
        }
        self.history.save()

        logger.info(f"Quality scan complete: {results['scanned']} functions, "
                   f"avg={results['avg_score']:.1f}%")

        return results

    def generate_quality_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive quality report.

        Returns:
            Dict with quality analysis:
            - overall_stats: Aggregate statistics
            - common_issues: Most frequent issues
            - improvement_areas: Prioritized areas for work
            - recent_changes: Recent quality changes
        """
        all_records = []
        for addr, records in self.history.records.items():
            if records:
                all_records.append(records[-1])  # Latest record for each function

        if not all_records:
            return {"message": "No quality data available"}

        # Calculate overall stats
        scores = [r["completeness_score"] for r in all_records]
        avg_score = sum(scores) / len(scores)

        # Count common issues
        issue_counts = {}
        for record in all_records:
            for issue in record.get("recommendations", []):
                issue_key = issue[:50]  # Truncate for grouping
                issue_counts[issue_key] = issue_counts.get(issue_key, 0) + 1

        # Sort by frequency
        common_issues = sorted(
            issue_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        # Find functions needing most work
        needs_work = sorted(
            [(r["address"], r["name"], r["completeness_score"], len(r.get("recommendations", [])))
             for r in all_records if r["completeness_score"] < 70],
            key=lambda x: x[2]  # Sort by score ascending
        )[:20]

        # Recent improvements
        improvements = []
        for addr, records in self.history.records.items():
            if len(records) >= 2:
                latest = records[-1]
                previous = records[-2]
                diff = latest["completeness_score"] - previous["completeness_score"]
                if diff != 0:
                    improvements.append({
                        "address": addr,
                        "name": latest["name"],
                        "change": diff,
                        "current": latest["completeness_score"],
                        "timestamp": latest["timestamp"]
                    })

        # Sort by change magnitude
        improvements.sort(key=lambda x: abs(x["change"]), reverse=True)

        report = {
            "generated_at": datetime.now().isoformat(),
            "overall_stats": {
                "total_functions": len(all_records),
                "avg_score": round(avg_score, 1),
                "min_score": min(scores),
                "max_score": max(scores),
                "below_50": sum(1 for s in scores if s < 50),
                "above_90": sum(1 for s in scores if s >= 90)
            },
            "common_issues": [
                {"issue": issue, "count": count}
                for issue, count in common_issues
            ],
            "needs_work": [
                {"address": addr, "name": name, "score": score, "issues": issues}
                for addr, name, score, issues in needs_work
            ],
            "recent_changes": improvements[:10],
            "summary": self.history.summary
        }

        return report

    def get_priority_queue(self, max_count: int = 20) -> List[Dict]:
        """
        Get a prioritized queue of functions to document.

        Prioritizes by:
        1. Low completeness score
        2. High issue count
        3. Not recently worked on

        Args:
            max_count: Maximum functions to return

        Returns:
            List of function dicts with priority info
        """
        all_records = []
        for addr, records in self.history.records.items():
            if records:
                latest = records[-1]
                # Calculate priority score (lower is higher priority)
                priority = latest["completeness_score"]
                # Boost priority for more issues
                priority -= len(latest.get("recommendations", [])) * 2

                all_records.append({
                    "address": addr,
                    "name": latest["name"],
                    "score": latest["completeness_score"],
                    "issues": len(latest.get("recommendations", [])),
                    "priority": priority,
                    "last_checked": latest["timestamp"]
                })

        # Sort by priority (ascending)
        all_records.sort(key=lambda x: x["priority"])

        return all_records[:max_count]


# =============================================================================
# Convenience functions
# =============================================================================

def check_quality(loop, func_address: str) -> Dict[str, Any]:
    """Quick quality check for a single function."""
    tracker = QualityTracker(loop)
    record = tracker.check_function_quality(func_address)
    return asdict(record)


def generate_report(loop) -> Dict[str, Any]:
    """Generate a quality report."""
    tracker = QualityTracker(loop)
    return tracker.generate_quality_report()


def get_priority_functions(loop, max_count: int = 20) -> List[Dict]:
    """Get prioritized list of functions to document."""
    tracker = QualityTracker(loop)
    return tracker.get_priority_queue(max_count)


# =============================================================================
# CLI
# =============================================================================

def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Quality Tracker")
    parser.add_argument("--report", action="store_true", help="Generate quality report")
    parser.add_argument("--summary", action="store_true", help="Show summary stats")

    args = parser.parse_args()

    history = QualityHistory.load()

    if args.report or args.summary:
        if history.summary:
            print(json.dumps(history.summary, indent=2))
        else:
            print("No quality data available. Run a quality scan first.")
        return 0

    # Default: show usage
    parser.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
