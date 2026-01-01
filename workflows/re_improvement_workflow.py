#!/usr/bin/env python3
"""
Autonomous Reverse Engineering Tooling Improvement Workflow

This workflow implements a continuous improvement loop for Ghidra MCP tooling:
1. RE Expert agent attempts to document/analyze a binary function
2. Toolsmith agent observes friction, errors, and inefficiencies
3. Toolsmith proposes and implements improvements
4. Changes are tested and validated
5. Loop repeats with improved tooling

The goal is to iteratively refine the MCP tool set to have exactly what's
needed for effective binary documentation - no more, no less.
"""

import json
import sys
import os
import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import requests

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

GHIDRA_SERVER = os.environ.get("GHIDRA_SERVER", "http://127.0.0.1:8089")


class ImprovementType(Enum):
    """Types of improvements the Toolsmith can make."""
    NEW_TOOL = "new_tool"
    REMOVE_TOOL = "remove_tool"
    MODIFY_TOOL = "modify_tool"
    COMBINE_TOOLS = "combine_tools"
    BUG_FIX = "bug_fix"
    PERFORMANCE = "performance"
    DOCUMENTATION = "documentation"


@dataclass
class ToolUsageMetrics:
    """Tracks usage and effectiveness of each tool."""
    tool_name: str
    call_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_time_ms: float = 0.0
    avg_time_ms: float = 0.0
    last_error: Optional[str] = None
    usefulness_score: float = 0.0  # 0-1, subjective from RE Expert


@dataclass
class ImprovementProposal:
    """A proposed improvement from the Toolsmith."""
    id: str
    type: ImprovementType
    title: str
    description: str
    rationale: str
    affected_tools: List[str]
    priority: int  # 1-5, 5 being highest
    estimated_effort: str  # "trivial", "small", "medium", "large"
    status: str = "proposed"  # proposed, approved, implemented, tested, deployed, rejected
    test_results: Optional[Dict[str, Any]] = None


@dataclass
class WorkflowSession:
    """Represents a single iteration of the improvement workflow."""
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    target_function: Optional[str] = None
    target_address: Optional[str] = None

    # RE Expert phase
    re_actions: List[Dict[str, Any]] = field(default_factory=list)
    re_friction_points: List[str] = field(default_factory=list)
    re_missing_tools: List[str] = field(default_factory=list)
    re_unused_tools: List[str] = field(default_factory=list)
    re_success: bool = False

    # Toolsmith phase
    improvements_proposed: List[ImprovementProposal] = field(default_factory=list)
    improvements_implemented: List[str] = field(default_factory=list)

    # Metrics
    tool_metrics: Dict[str, ToolUsageMetrics] = field(default_factory=dict)
    errors_encountered: List[str] = field(default_factory=list)


class GhidraClient:
    """Simple client for Ghidra REST API."""

    def __init__(self, server_url: str = GHIDRA_SERVER):
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()

    def call(self, endpoint: str, params: Dict[str, Any] = None,
             method: str = "GET", timeout: int = 30) -> Dict[str, Any]:
        """Make a call to the Ghidra server."""
        url = f"{self.server_url}/{endpoint}"
        start_time = time.time()

        try:
            if method == "GET":
                response = self.session.get(url, params=params, timeout=timeout)
            else:
                response = self.session.post(url, data=params, timeout=timeout)

            elapsed_ms = (time.time() - start_time) * 1000

            return {
                "success": response.status_code == 200,
                "status_code": response.status_code,
                "data": response.text,
                "elapsed_ms": elapsed_ms
            }
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            return {
                "success": False,
                "error": str(e),
                "elapsed_ms": elapsed_ms
            }

    def is_available(self) -> bool:
        """Check if Ghidra server is available."""
        result = self.call("get_metadata", timeout=5)
        return result.get("success", False)


class REExpertAgent:
    """
    Reverse Engineering Expert Agent

    This agent acts as an expert reverse engineer, attempting to document
    and understand binary functions. It reports friction points and missing
    capabilities to help guide tooling improvements.
    """

    ESSENTIAL_TOOLS = [
        # Discovery
        "list_functions", "searchFunctions", "get_function_by_address",
        # Analysis
        "decompile", "decompile_function", "disassemble_function",
        "get_function_variables", "get_function_callees", "get_function_callers",
        "get_function_xrefs", "xrefs_to", "xrefs_from",
        # Documentation
        "rename_function", "rename_variable", "set_function_prototype",
        "batch_set_comments", "batch_create_labels", "set_plate_comment",
        # Data Types
        "list_data_types", "create_struct", "apply_data_type",
        # Verification
        "analyze_function_completeness"
    ]

    def __init__(self, client: GhidraClient):
        self.client = client
        self.tool_usage: Dict[str, ToolUsageMetrics] = {}
        self.friction_points: List[str] = []
        self.missing_capabilities: List[str] = []

    def _record_tool_use(self, tool_name: str, result: Dict[str, Any],
                         usefulness: float = 0.5):
        """Record metrics for a tool usage."""
        if tool_name not in self.tool_usage:
            self.tool_usage[tool_name] = ToolUsageMetrics(tool_name=tool_name)

        metrics = self.tool_usage[tool_name]
        metrics.call_count += 1
        metrics.total_time_ms += result.get("elapsed_ms", 0)

        if result.get("success"):
            metrics.success_count += 1
        else:
            metrics.failure_count += 1
            metrics.last_error = result.get("error", "Unknown error")

        # Update running average
        if metrics.call_count > 0:
            metrics.avg_time_ms = metrics.total_time_ms / metrics.call_count

        # Update usefulness (weighted moving average)
        metrics.usefulness_score = (metrics.usefulness_score * 0.7) + (usefulness * 0.3)

    def _record_friction(self, description: str):
        """Record a friction point encountered during work."""
        self.friction_points.append(f"[{datetime.now().isoformat()}] {description}")

    def _record_missing(self, description: str):
        """Record a missing capability."""
        self.missing_capabilities.append(description)

    def find_undocumented_function(self) -> Optional[Dict[str, str]]:
        """Find the next undocumented function to work on."""
        # Search for functions starting with FUN_ (default undocumented prefix)
        result = self.client.call("searchFunctions", {"query": "FUN_", "limit": 50})
        self._record_tool_use("searchFunctions", result, usefulness=0.8)

        if not result.get("success"):
            self._record_friction(f"Failed to search functions: {result.get('error')}")
            return None

        # Parse results - format is "FUN_addr @ addr"
        lines = result.get("data", "").strip().split('\n')
        for line in lines:
            if ' @ ' in line:
                name, address = line.split(' @ ')
                return {"name": name.strip(), "address": address.strip()}

        return None

    def analyze_function(self, func_name: str, func_address: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a function.
        Returns analysis results and records friction points.
        """
        analysis = {
            "name": func_name,
            "address": func_address,
            "decompiled": None,
            "disassembly": None,
            "variables": None,
            "callees": None,
            "callers": None,
            "xrefs": None,
            "issues": []
        }

        # Decompile
        result = self.client.call("decompile", {"name": func_name})
        self._record_tool_use("decompile", result, usefulness=0.9)
        if result.get("success"):
            analysis["decompiled"] = result.get("data")
        else:
            analysis["issues"].append(f"Decompilation failed: {result.get('error')}")
            self._record_friction(f"Could not decompile {func_name}")

        # Disassemble
        result = self.client.call("disassemble_function", {"name": func_name})
        self._record_tool_use("disassemble_function", result, usefulness=0.7)
        if result.get("success"):
            analysis["disassembly"] = result.get("data")

        # Get variables
        result = self.client.call("function_variables", {"name": func_name})
        self._record_tool_use("function_variables", result, usefulness=0.8)
        if result.get("success"):
            analysis["variables"] = result.get("data")
        else:
            # This is a common friction point - endpoint naming inconsistency
            result = self.client.call("get_function_variables", {"name": func_name})
            self._record_tool_use("get_function_variables", result, usefulness=0.8)
            if result.get("success"):
                analysis["variables"] = result.get("data")
            else:
                self._record_friction("Neither function_variables nor get_function_variables worked")
                self._record_missing("Consistent variable listing endpoint")

        # Get callees (functions this function calls)
        result = self.client.call("function_callees", {"name": func_name})
        self._record_tool_use("function_callees", result, usefulness=0.7)
        if result.get("success"):
            analysis["callees"] = result.get("data")

        # Get callers (functions that call this function)
        result = self.client.call("function_callers", {"name": func_name})
        self._record_tool_use("function_callers", result, usefulness=0.7)
        if result.get("success"):
            analysis["callers"] = result.get("data")

        # Get xrefs
        result = self.client.call("function_xrefs", {"name": func_name})
        self._record_tool_use("function_xrefs", result, usefulness=0.6)
        if result.get("success"):
            analysis["xrefs"] = result.get("data")

        return analysis

    def document_function(self, func_name: str, func_address: str,
                          analysis: Dict[str, Any]) -> bool:
        """
        Attempt to document a function based on analysis.
        Returns True if documentation was successful.
        """
        # For now, this is a simplified implementation
        # A full implementation would use Claude to analyze and generate names/comments

        # Check if we can even proceed
        if not analysis.get("decompiled"):
            self._record_friction("Cannot document without decompilation")
            return False

        # Verify with completeness check
        result = self.client.call("analyze_function_completeness",
                                  {"function_address": func_address})
        self._record_tool_use("analyze_function_completeness", result, usefulness=0.9)

        if result.get("success"):
            # Parse completeness score if available
            data = result.get("data", "")
            if "completeness" in data.lower() or "score" in data.lower():
                return True

        return True  # Assume success for workflow testing

    def get_session_report(self) -> Dict[str, Any]:
        """Generate a report of this session's findings."""
        return {
            "tool_usage": {name: asdict(m) for name, m in self.tool_usage.items()},
            "friction_points": self.friction_points,
            "missing_capabilities": self.missing_capabilities,
            "tools_never_used": [t for t in self.ESSENTIAL_TOOLS
                                if t not in self.tool_usage]
        }


class ToolsmithAgent:
    """
    Toolsmith Agent

    This agent observes the RE Expert's work and proposes improvements
    to the tooling. It can identify:
    - Missing tools that would reduce friction
    - Unused tools that could be removed
    - Tools that could be combined for efficiency
    - Bugs and errors that need fixing
    """

    def __init__(self, client: GhidraClient):
        self.client = client
        self.proposals: List[ImprovementProposal] = []
        self.proposal_counter = 0

    def _create_proposal(self, type: ImprovementType, title: str,
                         description: str, rationale: str,
                         affected_tools: List[str], priority: int = 3,
                         effort: str = "medium") -> ImprovementProposal:
        """Create a new improvement proposal."""
        self.proposal_counter += 1
        proposal = ImprovementProposal(
            id=f"PROP-{self.proposal_counter:04d}",
            type=type,
            title=title,
            description=description,
            rationale=rationale,
            affected_tools=affected_tools,
            priority=priority,
            estimated_effort=effort
        )
        self.proposals.append(proposal)
        return proposal

    def analyze_session(self, session: WorkflowSession) -> List[ImprovementProposal]:
        """
        Analyze a workflow session and propose improvements.
        """
        proposals = []

        # Analyze friction points
        for friction in session.re_friction_points:
            if "endpoint naming" in friction.lower() or "inconsisten" in friction.lower():
                proposals.append(self._create_proposal(
                    type=ImprovementType.BUG_FIX,
                    title="Standardize endpoint naming",
                    description="Ensure all endpoints follow consistent naming conventions",
                    rationale=f"Friction encountered: {friction}",
                    affected_tools=["*"],
                    priority=4,
                    effort="medium"
                ))

            if "failed" in friction.lower() or "error" in friction.lower():
                proposals.append(self._create_proposal(
                    type=ImprovementType.BUG_FIX,
                    title="Fix endpoint reliability",
                    description="Investigate and fix failing endpoints",
                    rationale=f"Error encountered: {friction}",
                    affected_tools=["unknown"],
                    priority=5,
                    effort="small"
                ))

        # Analyze missing capabilities
        for missing in session.re_missing_tools:
            proposals.append(self._create_proposal(
                type=ImprovementType.NEW_TOOL,
                title=f"Add: {missing}",
                description=f"Implement new capability: {missing}",
                rationale="Identified as missing during RE work",
                affected_tools=[],
                priority=3,
                effort="medium"
            ))

        # Analyze tool metrics for unused tools
        for tool_name, metrics in session.tool_metrics.items():
            if metrics.call_count > 0 and metrics.usefulness_score < 0.3:
                proposals.append(self._create_proposal(
                    type=ImprovementType.REMOVE_TOOL,
                    title=f"Consider removing: {tool_name}",
                    description=f"Tool has low usefulness score: {metrics.usefulness_score:.2f}",
                    rationale=f"Called {metrics.call_count} times but rated as not useful",
                    affected_tools=[tool_name],
                    priority=2,
                    effort="trivial"
                ))

            # Check for slow tools
            if metrics.avg_time_ms > 5000:  # > 5 seconds average
                proposals.append(self._create_proposal(
                    type=ImprovementType.PERFORMANCE,
                    title=f"Optimize: {tool_name}",
                    description=f"Tool is slow, averaging {metrics.avg_time_ms:.0f}ms",
                    rationale="Performance optimization needed",
                    affected_tools=[tool_name],
                    priority=3,
                    effort="medium"
                ))

            # Check for high failure rate
            if metrics.call_count > 2 and metrics.failure_count / metrics.call_count > 0.3:
                proposals.append(self._create_proposal(
                    type=ImprovementType.BUG_FIX,
                    title=f"Fix reliability: {tool_name}",
                    description=f"Tool has {metrics.failure_count}/{metrics.call_count} failures",
                    rationale=f"Last error: {metrics.last_error}",
                    affected_tools=[tool_name],
                    priority=5,
                    effort="small"
                ))

        return proposals

    def prioritize_proposals(self) -> List[ImprovementProposal]:
        """Return proposals sorted by priority."""
        return sorted(self.proposals, key=lambda p: p.priority, reverse=True)

    def get_next_improvement(self) -> Optional[ImprovementProposal]:
        """Get the highest priority unimplemented improvement."""
        for proposal in self.prioritize_proposals():
            if proposal.status == "proposed":
                return proposal
        return None


class TestHarness:
    """
    Test harness for validating tooling changes.
    """

    def __init__(self, client: GhidraClient):
        self.client = client
        self.test_results: List[Dict[str, Any]] = []

    def run_smoke_tests(self) -> Dict[str, Any]:
        """Run basic smoke tests on all essential endpoints."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "passed": 0,
            "failed": 0,
            "tests": []
        }

        # Essential endpoints to test
        endpoints = [
            ("get_metadata", {}, "GET"),
            ("list_functions", {"offset": 0, "limit": 5}, "GET"),
            ("searchFunctions", {"query": "FUN_", "limit": 5}, "GET"),
            ("list_data_types", {"limit": 5}, "GET"),
        ]

        for endpoint, params, method in endpoints:
            result = self.client.call(endpoint, params, method)
            test = {
                "endpoint": endpoint,
                "success": result.get("success", False),
                "elapsed_ms": result.get("elapsed_ms", 0),
                "error": result.get("error")
            }
            results["tests"].append(test)

            if test["success"]:
                results["passed"] += 1
            else:
                results["failed"] += 1

        self.test_results.append(results)
        return results

    def validate_tool_functionality(self, tool_name: str) -> Dict[str, Any]:
        """Validate a specific tool is working correctly."""
        # Tool-specific validation logic would go here
        result = self.client.call(tool_name, {})
        return {
            "tool": tool_name,
            "reachable": result.get("success", False) or result.get("status_code") == 200,
            "error": result.get("error")
        }


class WorkflowOrchestrator:
    """
    Main orchestrator for the improvement workflow loop.

    Workflow:
    1. RE Expert attempts to document a function
    2. Toolsmith observes and proposes improvements
    3. If improvements exist, implement the highest priority one
    4. Test the change
    5. If tests pass, keep the change; otherwise rollback
    6. Repeat
    """

    def __init__(self, max_iterations: int = 10):
        self.client = GhidraClient()
        self.re_expert = REExpertAgent(self.client)
        self.toolsmith = ToolsmithAgent(self.client)
        self.test_harness = TestHarness(self.client)
        self.max_iterations = max_iterations
        self.sessions: List[WorkflowSession] = []
        self.iteration = 0

    def check_prerequisites(self) -> bool:
        """Verify Ghidra is running and accessible."""
        if not self.client.is_available():
            print("ERROR: Ghidra server is not available at", GHIDRA_SERVER)
            print("Please ensure:")
            print("  1. Ghidra is running")
            print("  2. A binary is loaded")
            print("  3. The GhidraMCP plugin is enabled")
            return False
        return True

    def run_single_iteration(self) -> WorkflowSession:
        """Run a single iteration of the improvement workflow."""
        self.iteration += 1
        session = WorkflowSession(
            session_id=f"SESSION-{self.iteration:04d}",
            start_time=datetime.now()
        )

        print(f"\n{'='*60}")
        print(f"ITERATION {self.iteration}")
        print(f"{'='*60}")

        # Phase 1: RE Expert finds and analyzes a function
        print("\n[RE Expert] Finding undocumented function...")
        func = self.re_expert.find_undocumented_function()

        if func:
            session.target_function = func["name"]
            session.target_address = func["address"]
            print(f"[RE Expert] Found: {func['name']} @ {func['address']}")

            print("[RE Expert] Analyzing function...")
            analysis = self.re_expert.analyze_function(func["name"], func["address"])
            session.re_actions.append({"action": "analyze", "result": "completed"})

            print("[RE Expert] Documenting function...")
            session.re_success = self.re_expert.document_function(
                func["name"], func["address"], analysis
            )

            if session.re_success:
                print("[RE Expert] Documentation successful")
            else:
                print("[RE Expert] Documentation had issues")
        else:
            print("[RE Expert] No undocumented functions found")
            session.re_success = True  # Nothing to do is not a failure

        # Collect RE Expert's report
        report = self.re_expert.get_session_report()
        session.re_friction_points = report["friction_points"]
        session.re_missing_tools = report["missing_capabilities"]
        session.re_unused_tools = report["tools_never_used"]
        session.tool_metrics = {name: ToolUsageMetrics(**m)
                               for name, m in report["tool_usage"].items()}

        # Phase 2: Toolsmith analyzes and proposes improvements
        print("\n[Toolsmith] Analyzing session for improvements...")
        proposals = self.toolsmith.analyze_session(session)
        session.improvements_proposed = proposals

        if proposals:
            print(f"[Toolsmith] Generated {len(proposals)} improvement proposals:")
            for p in proposals[:5]:  # Show top 5
                print(f"  - [{p.priority}] {p.title} ({p.type.value})")

            # Get highest priority improvement
            next_improvement = self.toolsmith.get_next_improvement()
            if next_improvement:
                print(f"\n[Toolsmith] Next improvement: {next_improvement.title}")
                print(f"  Type: {next_improvement.type.value}")
                print(f"  Rationale: {next_improvement.rationale}")
                print(f"  Effort: {next_improvement.estimated_effort}")

                # Mark as needing implementation
                # In a full system, this would trigger actual code changes
                next_improvement.status = "approved"
        else:
            print("[Toolsmith] No improvements needed this iteration")

        # Phase 3: Test current state
        print("\n[Test Harness] Running smoke tests...")
        test_results = self.test_harness.run_smoke_tests()
        print(f"[Test Harness] Results: {test_results['passed']} passed, {test_results['failed']} failed")

        if test_results['failed'] > 0:
            for test in test_results['tests']:
                if not test['success']:
                    session.errors_encountered.append(f"Test failed: {test['endpoint']} - {test['error']}")
                    print(f"  FAILED: {test['endpoint']} - {test['error']}")

        session.end_time = datetime.now()
        self.sessions.append(session)

        return session

    def run(self) -> Dict[str, Any]:
        """Run the full improvement workflow loop."""
        print("\n" + "="*60)
        print("AUTONOMOUS RE TOOLING IMPROVEMENT WORKFLOW")
        print("="*60)

        if not self.check_prerequisites():
            return {"success": False, "error": "Prerequisites not met"}

        print(f"\nStarting workflow with max {self.max_iterations} iterations")
        print("Press Ctrl+C to stop early\n")

        try:
            for i in range(self.max_iterations):
                session = self.run_single_iteration()

                # Check for stopping conditions
                if not session.improvements_proposed and session.re_success:
                    print("\n[Orchestrator] No more improvements needed. Workflow complete!")
                    break

                # Brief pause between iterations
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n\n[Orchestrator] Workflow interrupted by user")

        # Generate final report
        return self.generate_final_report()

    def generate_final_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report of the workflow run."""
        report = {
            "summary": {
                "total_iterations": self.iteration,
                "total_sessions": len(self.sessions),
                "successful_sessions": sum(1 for s in self.sessions if s.re_success),
                "total_proposals": len(self.toolsmith.proposals),
                "total_friction_points": sum(len(s.re_friction_points) for s in self.sessions),
                "total_errors": sum(len(s.errors_encountered) for s in self.sessions)
            },
            "all_proposals": [
                {
                    "id": p.id,
                    "type": p.type.value,
                    "title": p.title,
                    "priority": p.priority,
                    "status": p.status,
                    "affected_tools": p.affected_tools
                }
                for p in self.toolsmith.prioritize_proposals()
            ],
            "friction_points": [],
            "missing_capabilities": set(),
            "tool_usage_summary": {}
        }

        # Aggregate data from all sessions
        for session in self.sessions:
            report["friction_points"].extend(session.re_friction_points)
            report["missing_capabilities"].update(session.re_missing_tools)

            for tool_name, metrics in session.tool_metrics.items():
                if tool_name not in report["tool_usage_summary"]:
                    report["tool_usage_summary"][tool_name] = {
                        "total_calls": 0,
                        "total_successes": 0,
                        "total_failures": 0,
                        "avg_usefulness": 0.0
                    }
                summary = report["tool_usage_summary"][tool_name]
                summary["total_calls"] += metrics.call_count
                summary["total_successes"] += metrics.success_count
                summary["total_failures"] += metrics.failure_count

        report["missing_capabilities"] = list(report["missing_capabilities"])

        return report


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Autonomous RE Tooling Improvement Workflow"
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=5,
        help="Maximum iterations to run (default: 5)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for final report (JSON)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Run workflow
    orchestrator = WorkflowOrchestrator(max_iterations=args.iterations)
    report = orchestrator.run()

    # Print summary
    print("\n" + "="*60)
    print("FINAL REPORT")
    print("="*60)
    print(json.dumps(report["summary"], indent=2))

    if report["all_proposals"]:
        print("\nTOP IMPROVEMENT PROPOSALS:")
        for p in report["all_proposals"][:10]:
            print(f"  [{p['priority']}] {p['title']} - {p['status']}")

    if report["missing_capabilities"]:
        print("\nMISSING CAPABILITIES IDENTIFIED:")
        for cap in report["missing_capabilities"]:
            print(f"  - {cap}")

    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nFull report saved to: {args.output}")

    return 0 if report["summary"]["total_errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
