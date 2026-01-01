#!/usr/bin/env python3
"""
Self-Improvement System for Ghidra MCP Tooling

This module provides continuous self-improvement capabilities:
1. Error/friction tracking - Captures tool failures and patterns
2. Issue-based remediation - Fixes specific issues without full reprocessing
3. Tool health monitoring - Detects degraded MCP tools
4. Improvement proposals - Suggests and tracks tooling enhancements
5. Interval-based quality audits - Regular checks for regressions

Usage:
    from workflows.self_improvement import SelfImprovementEngine

    engine = SelfImprovementEngine()
    engine.run_improvement_cycle()
"""

import json
import re
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging

# Setup
REPO_ROOT = Path(__file__).parent.parent
STATE_DIR = Path(__file__).parent
LOG_DIR = STATE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger('self_improvement')
logger.setLevel(logging.INFO)

if not logger.handlers:
    fh = logging.FileHandler(LOG_DIR / f"self_improvement_{datetime.now():%Y%m%d}.log", encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)
    logger.addHandler(logging.StreamHandler())


class IssueType(Enum):
    """Types of issues that can be tracked."""
    MCP_ERROR = "mcp_error"              # Tool returned error
    MCP_TIMEOUT = "mcp_timeout"          # Tool timed out
    MCP_INVALID_RESPONSE = "mcp_invalid" # Tool returned malformed data
    QUALITY_MISSING_NAME = "quality_name"
    QUALITY_MISSING_PROTOTYPE = "quality_prototype"
    QUALITY_MISSING_TYPES = "quality_types"
    QUALITY_MISSING_COMMENT = "quality_comment"
    QUALITY_HUNGARIAN_VIOLATION = "quality_hungarian"
    QUALITY_PLATE_INCOMPLETE = "quality_plate"
    WORKFLOW_FRICTION = "workflow_friction"
    TOOL_SUGGESTION = "tool_suggestion"


class IssueSeverity(Enum):
    """Severity levels for issues."""
    LOW = "low"           # Minor inconvenience
    MEDIUM = "medium"     # Affects quality
    HIGH = "high"         # Blocks progress
    CRITICAL = "critical" # System unusable


@dataclass
class Issue:
    """A tracked issue requiring attention."""
    id: str
    issue_type: str
    severity: str
    description: str
    context: Dict[str, Any]
    created_at: str
    resolved_at: Optional[str] = None
    resolution: Optional[str] = None
    attempts: int = 0
    last_attempt: Optional[str] = None

    # For function-specific issues
    function_address: Optional[str] = None
    function_name: Optional[str] = None

    # For tool issues
    tool_name: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class ToolHealthRecord:
    """Health status of an MCP tool."""
    tool_name: str
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    total_time_ms: float = 0
    last_error: Optional[str] = None
    last_error_time: Optional[str] = None
    consecutive_failures: int = 0
    status: str = "healthy"  # healthy, degraded, failing


@dataclass
class ImprovementProposal:
    """A proposed improvement to the tooling."""
    id: str
    category: str  # mcp_tool, slash_command, workflow, quality_check
    title: str
    description: str
    rationale: str
    priority: int  # 1-5, 1 is highest
    status: str = "proposed"  # proposed, approved, implemented, rejected
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    implemented_at: Optional[str] = None
    implementation_notes: Optional[str] = None


@dataclass
class SelfImprovementState:
    """Persistent state for self-improvement system."""
    # Issue tracking
    open_issues: List[Dict] = field(default_factory=list)
    resolved_issues: List[Dict] = field(default_factory=list)

    # Tool health
    tool_health: Dict[str, Dict] = field(default_factory=dict)

    # Improvement proposals
    proposals: List[Dict] = field(default_factory=list)

    # Statistics
    cycles_run: int = 0
    issues_created: int = 0
    issues_resolved: int = 0
    last_cycle: Optional[str] = None
    last_quality_audit: Optional[str] = None
    last_tool_health_check: Optional[str] = None

    def save(self):
        path = STATE_DIR / ".self_improvement_state.json"
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> 'SelfImprovementState':
        path = STATE_DIR / ".self_improvement_state.json"
        if path.exists():
            try:
                with open(path) as f:
                    return cls(**json.load(f))
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()


class IssueTracker:
    """Tracks and manages issues for remediation."""

    def __init__(self, state: SelfImprovementState):
        self.state = state
        self._issue_counter = state.issues_created

    def create_issue(
        self,
        issue_type: IssueType,
        severity: IssueSeverity,
        description: str,
        context: Dict[str, Any] = None,
        function_address: str = None,
        function_name: str = None,
        tool_name: str = None,
        error_message: str = None
    ) -> Issue:
        """Create and track a new issue."""
        self._issue_counter += 1

        issue = Issue(
            id=f"ISSUE-{self._issue_counter:05d}",
            issue_type=issue_type.value,
            severity=severity.value,
            description=description,
            context=context or {},
            created_at=datetime.now().isoformat(),
            function_address=function_address,
            function_name=function_name,
            tool_name=tool_name,
            error_message=error_message
        )

        self.state.open_issues.append(asdict(issue))
        self.state.issues_created = self._issue_counter
        self.state.save()

        logger.info(f"Created issue {issue.id}: {description}")
        return issue

    def resolve_issue(self, issue_id: str, resolution: str):
        """Mark an issue as resolved."""
        for i, issue_dict in enumerate(self.state.open_issues):
            if issue_dict["id"] == issue_id:
                issue_dict["resolved_at"] = datetime.now().isoformat()
                issue_dict["resolution"] = resolution
                self.state.resolved_issues.append(issue_dict)
                self.state.open_issues.pop(i)
                self.state.issues_resolved += 1
                self.state.save()
                logger.info(f"Resolved issue {issue_id}: {resolution}")
                return True
        return False

    def get_open_issues(self,
                        issue_type: IssueType = None,
                        severity: IssueSeverity = None,
                        function_address: str = None) -> List[Dict]:
        """Get open issues with optional filtering."""
        issues = self.state.open_issues

        if issue_type:
            issues = [i for i in issues if i["issue_type"] == issue_type.value]
        if severity:
            issues = [i for i in issues if i["severity"] == severity.value]
        if function_address:
            issues = [i for i in issues if i.get("function_address") == function_address]

        return issues

    def get_issues_for_function(self, function_address: str) -> List[Dict]:
        """Get all open issues for a specific function."""
        return [i for i in self.state.open_issues
                if i.get("function_address") == function_address]

    def get_priority_issues(self, limit: int = 10) -> List[Dict]:
        """Get highest priority issues to work on."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        sorted_issues = sorted(
            self.state.open_issues,
            key=lambda i: (severity_order.get(i["severity"], 4), i["created_at"])
        )

        return sorted_issues[:limit]


class ToolHealthMonitor:
    """Monitors health of MCP tools."""

    def __init__(self, state: SelfImprovementState, ghidra_client):
        self.state = state
        self.client = ghidra_client

    def record_call(self, tool_name: str, success: bool, duration_ms: float, error: str = None):
        """Record a tool call for health tracking."""
        if tool_name not in self.state.tool_health:
            self.state.tool_health[tool_name] = asdict(ToolHealthRecord(tool_name=tool_name))

        health = self.state.tool_health[tool_name]
        health["total_calls"] += 1
        health["total_time_ms"] += duration_ms

        if success:
            health["successful_calls"] += 1
            health["consecutive_failures"] = 0
        else:
            health["failed_calls"] += 1
            health["consecutive_failures"] += 1
            health["last_error"] = error
            health["last_error_time"] = datetime.now().isoformat()

        # Update status
        if health["consecutive_failures"] >= 5:
            health["status"] = "failing"
        elif health["consecutive_failures"] >= 2:
            health["status"] = "degraded"
        elif health["total_calls"] > 0:
            success_rate = health["successful_calls"] / health["total_calls"]
            health["status"] = "healthy" if success_rate > 0.9 else "degraded"

        self.state.save()

    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary."""
        tools = self.state.tool_health

        if not tools:
            return {"status": "unknown", "message": "No tool calls recorded"}

        failing = [t for t, h in tools.items() if h["status"] == "failing"]
        degraded = [t for t, h in tools.items() if h["status"] == "degraded"]

        total_calls = sum(h["total_calls"] for h in tools.values())
        total_failures = sum(h["failed_calls"] for h in tools.values())

        return {
            "overall_status": "failing" if failing else ("degraded" if degraded else "healthy"),
            "total_tools": len(tools),
            "failing_tools": failing,
            "degraded_tools": degraded,
            "total_calls": total_calls,
            "total_failures": total_failures,
            "success_rate": (total_calls - total_failures) / total_calls if total_calls > 0 else 0
        }

    def run_health_check(self) -> Dict[str, Any]:
        """Run active health check on critical tools."""
        critical_tools = [
            ("decompile", {"name": "main"}),
            ("searchFunctions", {"query": "FUN_", "limit": 1}),
            ("get_metadata", {}),
        ]

        results = {}

        for tool_name, params in critical_tools:
            start = time.time()
            try:
                result = self.client.call(tool_name, params, timeout=10)
                duration = (time.time() - start) * 1000
                success = result.get("success", False)
                error = result.get("error") if not success else None

                self.record_call(tool_name, success, duration, error)
                results[tool_name] = {"status": "ok" if success else "error", "duration_ms": duration}

            except Exception as e:
                duration = (time.time() - start) * 1000
                self.record_call(tool_name, False, duration, str(e))
                results[tool_name] = {"status": "error", "error": str(e)}

        self.state.last_tool_health_check = datetime.now().isoformat()
        self.state.save()

        return results


class QualityAuditor:
    """Audits function documentation quality and creates targeted issues."""

    def __init__(self, state: SelfImprovementState, issue_tracker: IssueTracker, ghidra_client):
        self.state = state
        self.issues = issue_tracker
        self.client = ghidra_client

        # Initialize bookmark tracker for progress persistence
        self.bookmark_tracker = None
        try:
            from workflows.bookmark_tracker import BookmarkProgressTracker
            self.bookmark_tracker = BookmarkProgressTracker(ghidra_client)
        except ImportError:
            try:
                from bookmark_tracker import BookmarkProgressTracker
                self.bookmark_tracker = BookmarkProgressTracker(ghidra_client)
            except ImportError:
                logger.warning("BookmarkProgressTracker not available - progress won't be saved to bookmarks")

    def audit_function(self, function_address: str, function_name: str = None) -> Dict[str, Any]:
        """
        Audit a single function and create issues for specific problems.

        Returns dict with:
        - score: completeness score
        - issues_created: list of new issue IDs
        - existing_issues: list of existing issue IDs for this function
        """
        result = self.client.call("analyze_function_completeness",
                                  {"function_address": function_address})

        if not result.get("success"):
            return {"error": result.get("error", "Unknown error")}

        try:
            data = json.loads(result.get("data", "{}"))
        except json.JSONDecodeError:
            return {"error": "Invalid completeness data"}

        score = data.get("completeness_score", 0)
        issues_created = []

        # Check for existing issues to avoid duplicates
        existing = self.issues.get_issues_for_function(function_address)
        existing_types = {i["issue_type"] for i in existing}

        # Create issues for specific problems (only if not already tracked)

        if not data.get("has_custom_name") and IssueType.QUALITY_MISSING_NAME.value not in existing_types:
            issue = self.issues.create_issue(
                IssueType.QUALITY_MISSING_NAME,
                IssueSeverity.MEDIUM,
                f"Function needs meaningful name (currently {function_name or function_address})",
                context={"current_name": function_name},
                function_address=function_address,
                function_name=function_name
            )
            issues_created.append(issue.id)

        if not data.get("has_prototype") and IssueType.QUALITY_MISSING_PROTOTYPE.value not in existing_types:
            issue = self.issues.create_issue(
                IssueType.QUALITY_MISSING_PROTOTYPE,
                IssueSeverity.MEDIUM,
                "Function needs proper prototype with typed parameters",
                function_address=function_address,
                function_name=function_name
            )
            issues_created.append(issue.id)

        undefined_vars = data.get("undefined_variables", [])
        if undefined_vars and IssueType.QUALITY_MISSING_TYPES.value not in existing_types:
            issue = self.issues.create_issue(
                IssueType.QUALITY_MISSING_TYPES,
                IssueSeverity.LOW,
                f"Variables need types: {', '.join(undefined_vars[:5])}{'...' if len(undefined_vars) > 5 else ''}",
                context={"variables": undefined_vars},
                function_address=function_address,
                function_name=function_name
            )
            issues_created.append(issue.id)

        hungarian_violations = data.get("hungarian_notation_violations", [])
        if hungarian_violations and IssueType.QUALITY_HUNGARIAN_VIOLATION.value not in existing_types:
            issue = self.issues.create_issue(
                IssueType.QUALITY_HUNGARIAN_VIOLATION,
                IssueSeverity.LOW,
                f"Hungarian notation violations: {len(hungarian_violations)} variables",
                context={"violations": hungarian_violations[:10]},
                function_address=function_address,
                function_name=function_name
            )
            issues_created.append(issue.id)

        plate_issues = data.get("plate_comment_issues", [])
        if plate_issues and IssueType.QUALITY_PLATE_INCOMPLETE.value not in existing_types:
            issue = self.issues.create_issue(
                IssueType.QUALITY_PLATE_INCOMPLETE,
                IssueSeverity.LOW,
                f"Plate comment issues: {', '.join(plate_issues[:3])}",
                context={"issues": plate_issues},
                function_address=function_address,
                function_name=function_name
            )
            issues_created.append(issue.id)

        # Save progress to Ghidra bookmark for persistence
        bookmark_saved = False
        if self.bookmark_tracker:
            try:
                bookmark_saved = self.bookmark_tracker.update_from_completeness(
                    function_address, data
                )
            except Exception as e:
                logger.warning(f"Failed to save progress bookmark: {e}")

        return {
            "score": score,
            "issues_created": issues_created,
            "existing_issues": [i["id"] for i in existing],
            "recommendations": data.get("recommendations", []),
            "bookmark_saved": bookmark_saved
        }

    def get_progress_from_bookmarks(self) -> Dict[str, Any]:
        """Get overall progress from Ghidra bookmarks."""
        if not self.bookmark_tracker:
            return {"error": "Bookmark tracker not available"}
        return self.bookmark_tracker.get_overall_progress()

    def run_quality_audit(self, sample_size: int = 20) -> Dict[str, Any]:
        """Run quality audit on a sample of functions."""
        # Get recently documented functions (non-FUN_ names)
        result = self.client.call("searchFunctions", {"query": "", "limit": sample_size * 2})

        if not result.get("success"):
            return {"error": "Could not fetch functions"}

        functions = []
        for line in result.get("data", "").strip().split('\n'):
            if ' @ ' in line and not line.startswith('FUN_'):
                name, addr = line.split(' @ ')
                functions.append({"name": name.strip(), "address": addr.strip()})

        if not functions:
            return {"message": "No documented functions to audit"}

        audit_results = []
        total_score = 0
        issues_created = 0

        for func in functions[:sample_size]:
            result = self.audit_function(func["address"], func["name"])
            audit_results.append({
                "function": func["name"],
                "address": func["address"],
                **result
            })
            if "score" in result:
                total_score += result["score"]
                issues_created += len(result.get("issues_created", []))

        self.state.last_quality_audit = datetime.now().isoformat()
        self.state.save()

        return {
            "functions_audited": len(audit_results),
            "average_score": total_score / len(audit_results) if audit_results else 0,
            "issues_created": issues_created,
            "results": audit_results
        }


class IssueRemediator:
    """Remediates specific issues without full function reprocessing."""

    def __init__(self, ghidra_client, issue_tracker: IssueTracker):
        self.client = ghidra_client
        self.issues = issue_tracker

    def remediate_issue(self, issue: Dict) -> Tuple[bool, str]:
        """
        Attempt to remediate a specific issue.

        Returns (success, message)
        """
        issue_type = issue["issue_type"]
        func_addr = issue.get("function_address")

        if not func_addr:
            return False, "No function address in issue"

        # Update attempt tracking
        issue["attempts"] = issue.get("attempts", 0) + 1
        issue["last_attempt"] = datetime.now().isoformat()
        self.issues.state.save()

        # Dispatch to specific remediation handlers
        handlers = {
            IssueType.QUALITY_MISSING_NAME.value: self._remediate_missing_name,
            IssueType.QUALITY_MISSING_PROTOTYPE.value: self._remediate_missing_prototype,
            IssueType.QUALITY_MISSING_TYPES.value: self._remediate_missing_types,
            IssueType.QUALITY_PLATE_INCOMPLETE.value: self._remediate_plate_comment,
        }

        handler = handlers.get(issue_type)
        if not handler:
            return False, f"No remediation handler for {issue_type}"

        try:
            success, message = handler(issue)

            if success:
                self.issues.resolve_issue(issue["id"], message)

            return success, message

        except Exception as e:
            logger.error(f"Remediation failed: {e}")
            return False, str(e)

    def _remediate_missing_name(self, issue: Dict) -> Tuple[bool, str]:
        """This requires Claude analysis - return instructions."""
        # We can't auto-fix naming without AI analysis
        # Instead, return specific guidance
        return False, "NEEDS_CLAUDE: Analyze function and suggest name"

    def _remediate_missing_prototype(self, issue: Dict) -> Tuple[bool, str]:
        """This requires Claude analysis - return instructions."""
        return False, "NEEDS_CLAUDE: Analyze function and set prototype"

    def _remediate_missing_types(self, issue: Dict) -> Tuple[bool, str]:
        """Attempt to infer types from context."""
        func_addr = issue["function_address"]
        variables = issue.get("context", {}).get("variables", [])

        if not variables:
            return False, "No variables to type"

        # Try to get decompiled code for context
        result = self.client.call("decompile", {"name": issue.get("function_name", func_addr)})
        if not result.get("success"):
            return False, "NEEDS_CLAUDE: Could not decompile for type inference"

        # Basic type inference (very limited without Claude)
        # Just flag for Claude analysis
        return False, f"NEEDS_CLAUDE: Type {len(variables)} variables"

    def _remediate_plate_comment(self, issue: Dict) -> Tuple[bool, str]:
        """This requires Claude analysis - return instructions."""
        return False, "NEEDS_CLAUDE: Improve plate comment"

    def get_remediable_issues(self) -> List[Dict]:
        """Get issues that can potentially be auto-remediated."""
        # Currently most issues need Claude, but we track them
        return self.issues.get_priority_issues(limit=20)


class SelfImprovementEngine:
    """
    Main engine for continuous self-improvement.

    Coordinates all improvement activities:
    - Error tracking
    - Quality auditing
    - Issue remediation
    - Tool health monitoring
    - Improvement proposals
    """

    def __init__(self, ghidra_client=None):
        self.state = SelfImprovementState.load()

        # Initialize Ghidra client if not provided
        if ghidra_client is None:
            import sys
            # Add both possible paths
            sys.path.insert(0, str(REPO_ROOT))
            sys.path.insert(0, str(STATE_DIR))
            try:
                from re_improvement_workflow import GhidraClient
            except ImportError:
                try:
                    from workflows.re_improvement_workflow import GhidraClient
                except ImportError:
                    # Fallback: define minimal client inline
                    class GhidraClient:
                        def __init__(self):
                            import requests
                            self.server = "http://127.0.0.1:8089"
                        def call(self, endpoint, params=None, method="GET", timeout=30):
                            import requests
                            try:
                                url = f"{self.server}/{endpoint}"
                                if method == "GET":
                                    r = requests.get(url, params=params, timeout=timeout)
                                else:
                                    r = requests.post(url, json=params, timeout=timeout)
                                return {"success": r.status_code == 200, "data": r.text}
                            except Exception as e:
                                return {"success": False, "error": str(e)}
            ghidra_client = GhidraClient()

        self.client = ghidra_client
        self.issues = IssueTracker(self.state)
        self.health = ToolHealthMonitor(self.state, ghidra_client)
        self.auditor = QualityAuditor(self.state, self.issues, ghidra_client)
        self.remediator = IssueRemediator(ghidra_client, self.issues)

    def record_tool_error(self, tool_name: str, error: str, context: Dict = None):
        """Record a tool error for tracking and improvement."""
        self.issues.create_issue(
            IssueType.MCP_ERROR,
            IssueSeverity.HIGH,
            f"Tool '{tool_name}' failed: {error[:100]}",
            context={"tool": tool_name, "error": error, **(context or {})},
            tool_name=tool_name,
            error_message=error
        )
        self.health.record_call(tool_name, False, 0, error)

    def record_friction(self, description: str, context: Dict = None):
        """Record a workflow friction point."""
        self.issues.create_issue(
            IssueType.WORKFLOW_FRICTION,
            IssueSeverity.MEDIUM,
            description,
            context=context or {}
        )

    def propose_improvement(
        self,
        category: str,
        title: str,
        description: str,
        rationale: str,
        priority: int = 3
    ) -> str:
        """Create an improvement proposal."""
        proposal_id = f"PROP-{len(self.state.proposals) + 1:04d}"

        proposal = ImprovementProposal(
            id=proposal_id,
            category=category,
            title=title,
            description=description,
            rationale=rationale,
            priority=priority
        )

        self.state.proposals.append(asdict(proposal))
        self.state.save()

        logger.info(f"Created proposal {proposal_id}: {title}")
        return proposal_id

    def run_improvement_cycle(self) -> Dict[str, Any]:
        """
        Run a complete improvement cycle.

        This should be called periodically (e.g., every 10 functions documented).
        """
        logger.info("Starting improvement cycle...")
        cycle_results = {
            "timestamp": datetime.now().isoformat(),
            "health_check": None,
            "quality_audit": None,
            "issues_processed": 0,
            "remediations_attempted": 0,
            "proposals_created": 0
        }

        # 1. Tool health check
        logger.info("Running tool health check...")
        cycle_results["health_check"] = self.health.run_health_check()
        health_summary = self.health.get_health_summary()

        # Create issues for failing tools
        for tool in health_summary.get("failing_tools", []):
            existing = [i for i in self.state.open_issues
                       if i.get("tool_name") == tool and i["issue_type"] == IssueType.MCP_ERROR.value]
            if not existing:
                self.issues.create_issue(
                    IssueType.MCP_ERROR,
                    IssueSeverity.CRITICAL,
                    f"Tool '{tool}' is failing consistently",
                    tool_name=tool
                )

        # 2. Quality audit (sample)
        logger.info("Running quality audit...")
        cycle_results["quality_audit"] = self.auditor.run_quality_audit(sample_size=10)

        # 3. Process high-priority issues
        priority_issues = self.issues.get_priority_issues(limit=5)
        for issue in priority_issues:
            cycle_results["issues_processed"] += 1

            # Attempt remediation
            success, message = self.remediator.remediate_issue(issue)
            if success:
                cycle_results["remediations_attempted"] += 1
            elif message.startswith("NEEDS_CLAUDE"):
                # Log that this needs Claude attention
                logger.info(f"Issue {issue['id']} needs Claude: {message}")

        # 4. Analyze patterns and create proposals
        self._analyze_and_propose(cycle_results)

        # Update cycle stats
        self.state.cycles_run += 1
        self.state.last_cycle = datetime.now().isoformat()
        self.state.save()

        logger.info(f"Improvement cycle complete: {cycle_results}")
        return cycle_results

    def _analyze_and_propose(self, cycle_results: Dict):
        """Analyze patterns and create improvement proposals."""
        # Check for recurring tool errors
        tool_errors = [i for i in self.state.open_issues
                      if i["issue_type"] == IssueType.MCP_ERROR.value]

        error_counts = {}
        for issue in tool_errors:
            tool = issue.get("tool_name", "unknown")
            error_counts[tool] = error_counts.get(tool, 0) + 1

        for tool, count in error_counts.items():
            if count >= 3:
                # Check if we already proposed fixing this
                existing = [p for p in self.state.proposals
                           if tool in p.get("title", "") and p["status"] == "proposed"]
                if not existing:
                    self.propose_improvement(
                        category="mcp_tool",
                        title=f"Fix reliability issues in {tool}",
                        description=f"Tool '{tool}' has {count} open error issues. Investigate and fix.",
                        rationale=f"Recurring errors blocking workflow",
                        priority=1
                    )
                    cycle_results["proposals_created"] = cycle_results.get("proposals_created", 0) + 1

        # Check for quality patterns
        quality_issues = [i for i in self.state.open_issues
                         if i["issue_type"].startswith("quality_")]

        if len(quality_issues) > 20:
            type_counts = {}
            for issue in quality_issues:
                t = issue["issue_type"]
                type_counts[t] = type_counts.get(t, 0) + 1

            # Most common quality issue
            top_issue = max(type_counts.items(), key=lambda x: x[1])
            if top_issue[1] >= 5:
                existing = [p for p in self.state.proposals
                           if top_issue[0] in p.get("description", "") and p["status"] == "proposed"]
                if not existing:
                    self.propose_improvement(
                        category="workflow",
                        title=f"Address common quality issue: {top_issue[0]}",
                        description=f"{top_issue[1]} functions have {top_issue[0]} issues. Improve workflow to prevent.",
                        rationale="Recurring pattern in documentation quality",
                        priority=2
                    )

    def get_status(self) -> Dict[str, Any]:
        """Get current self-improvement status."""
        return {
            "cycles_run": self.state.cycles_run,
            "last_cycle": self.state.last_cycle,
            "open_issues": len(self.state.open_issues),
            "resolved_issues": self.state.issues_resolved,
            "active_proposals": len([p for p in self.state.proposals if p["status"] == "proposed"]),
            "tool_health": self.health.get_health_summary(),
            "priority_issues": self.issues.get_priority_issues(limit=5)
        }

    def get_claude_work_queue(self) -> List[Dict]:
        """
        Get issues that need Claude's attention.

        Returns prioritized list of issues with specific instructions.
        """
        work_queue = []

        for issue in self.issues.get_priority_issues(limit=20):
            # Determine what Claude needs to do
            issue_type = issue["issue_type"]

            if issue_type == IssueType.QUALITY_MISSING_NAME.value:
                work_queue.append({
                    "issue_id": issue["id"],
                    "action": "rename_function",
                    "function": issue.get("function_name") or issue.get("function_address"),
                    "address": issue.get("function_address"),
                    "instruction": "Decompile, analyze purpose, and rename to meaningful PascalCase name"
                })

            elif issue_type == IssueType.QUALITY_MISSING_PROTOTYPE.value:
                work_queue.append({
                    "issue_id": issue["id"],
                    "action": "set_prototype",
                    "function": issue.get("function_name") or issue.get("function_address"),
                    "address": issue.get("function_address"),
                    "instruction": "Analyze parameters and return type, set proper prototype"
                })

            elif issue_type == IssueType.QUALITY_MISSING_TYPES.value:
                work_queue.append({
                    "issue_id": issue["id"],
                    "action": "type_variables",
                    "function": issue.get("function_name") or issue.get("function_address"),
                    "address": issue.get("function_address"),
                    "variables": issue.get("context", {}).get("variables", []),
                    "instruction": "Analyze and type these specific variables with Hungarian notation"
                })

            elif issue_type == IssueType.QUALITY_PLATE_INCOMPLETE.value:
                work_queue.append({
                    "issue_id": issue["id"],
                    "action": "improve_comment",
                    "function": issue.get("function_name") or issue.get("function_address"),
                    "address": issue.get("function_address"),
                    "issues": issue.get("context", {}).get("issues", []),
                    "instruction": "Improve plate comment to meet requirements"
                })

        return work_queue


# =============================================================================
# Integration with workflow
# =============================================================================

def wrap_tool_call(engine: SelfImprovementEngine, tool_name: str, call_func: Callable) -> Callable:
    """Wrap a tool call to automatically track health and errors."""
    def wrapped(*args, **kwargs):
        start = time.time()
        try:
            result = call_func(*args, **kwargs)
            duration = (time.time() - start) * 1000

            success = result.get("success", False) if isinstance(result, dict) else True
            error = result.get("error") if isinstance(result, dict) and not success else None

            engine.health.record_call(tool_name, success, duration, error)

            if not success and error:
                engine.record_tool_error(tool_name, error, {"args": str(args)[:200]})

            return result

        except Exception as e:
            duration = (time.time() - start) * 1000
            engine.health.record_call(tool_name, False, duration, str(e))
            engine.record_tool_error(tool_name, str(e), {"args": str(args)[:200]})
            raise

    return wrapped


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Self-Improvement Engine")
    parser.add_argument("--status", action="store_true", help="Show current status")
    parser.add_argument("--cycle", action="store_true", help="Run improvement cycle")
    parser.add_argument("--issues", action="store_true", help="Show open issues")
    parser.add_argument("--work-queue", action="store_true", help="Show Claude work queue")
    parser.add_argument("--proposals", action="store_true", help="Show improvement proposals")

    args = parser.parse_args()

    engine = SelfImprovementEngine()

    if args.status:
        print(json.dumps(engine.get_status(), indent=2))
    elif args.cycle:
        result = engine.run_improvement_cycle()
        print(json.dumps(result, indent=2))
    elif args.issues:
        issues = engine.issues.get_priority_issues(limit=20)
        print(json.dumps(issues, indent=2))
    elif args.work_queue:
        queue = engine.get_claude_work_queue()
        print(json.dumps(queue, indent=2))
    elif args.proposals:
        proposals = [p for p in engine.state.proposals if p["status"] == "proposed"]
        print(json.dumps(proposals, indent=2))
    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
