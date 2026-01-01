#!/usr/bin/env python3
"""
Autonomous Self-Improving Documentation Loop

This is the main entry point for fully autonomous operation. It combines:
1. Function documentation
2. Issue-specific remediation
3. Tool health monitoring
4. Periodic improvement cycles
5. Error recovery

Usage:
    # Run autonomously with Claude Code
    python autonomous_loop.py --mode claude

    # Check status
    python autonomous_loop.py --status

    # Run improvement cycle only
    python autonomous_loop.py --improve

Architecture:
    autonomous_loop.py (this file)
        |
        +-> SelfImprovementEngine (self_improvement.py)
        |       - Issue tracking
        |       - Tool health
        |       - Quality auditing
        |
        +-> ContinuousImprovementLoop (continuous_improvement.py)
        |       - Ghidra interaction
        |       - Function processing
        |
        +-> Claude Code (external)
                - Function analysis
                - Issue remediation
"""

import json
import subprocess
import sys
import time
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

# Setup paths
WORKFLOW_DIR = Path(__file__).parent
REPO_ROOT = WORKFLOW_DIR.parent
LOG_DIR = WORKFLOW_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"autonomous_loop_{datetime.now():%Y%m%d_%H%M%S}.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import our modules
sys.path.insert(0, str(REPO_ROOT))
from workflows.self_improvement import SelfImprovementEngine
from workflows.continuous_improvement import ContinuousImprovementLoop


# Prompts for Claude Code
DOCUMENT_FUNCTION_PROMPT = """You are documenting a function in Ghidra. Work silently and efficiently.

Target: {function_name} @ {function_address}

Steps:
1. Decompile the function
2. Analyze purpose, parameters, and return value
3. Determine appropriate PascalCase name
4. Set function prototype with proper types
5. Type variables using Hungarian notation (dwFlags, pBuffer, nCount)
6. Add plate comment (3-5 lines: purpose, algorithm, returns)
7. Verify with analyze_function_completeness

Output ONLY this JSON:
{{"status": "success", "new_name": "Name", "score": 85}}
or {{"status": "error", "message": "reason"}}
"""

REMEDIATE_ISSUE_PROMPT = """You are fixing a specific documentation issue. Do NOT reprocess the entire function.

Issue: {issue_type}
Function: {function_name} @ {function_address}
Specific Problem: {description}
{context}

Fix ONLY this specific issue:
{instruction}

Output ONLY this JSON:
{{"status": "fixed", "action": "what you did"}}
or {{"status": "error", "message": "reason"}}
"""

IMPROVEMENT_CYCLE_PROMPT = """Run a self-improvement cycle. Check for:
1. Tool errors that need investigation
2. Quality patterns that indicate workflow issues
3. Proposed improvements that should be implemented

Review the current state:
- Open issues: {open_issues}
- Tool health: {tool_health}
- Proposals: {proposals}

Take action on the highest priority items. Output JSON:
{{"actions_taken": ["action1", "action2"], "proposals": ["new proposal if any"]}}
"""


class AutonomousLoop:
    """
    Main orchestrator for autonomous self-improving documentation.
    """

    def __init__(self):
        self.improvement_engine = SelfImprovementEngine()
        self.loop = ContinuousImprovementLoop()

        # Configuration
        self.improvement_interval = 10  # Run improvement cycle every N functions
        self.health_check_interval = 5  # Check tool health every N functions
        self.max_consecutive_errors = 3

        # Session state
        self.functions_processed = 0
        self.errors_this_session = 0
        self.consecutive_errors = 0
        self.session_start = datetime.now()

    def run_claude(self, prompt: str, timeout: int = 300) -> Dict[str, Any]:
        """Run Claude Code with a prompt."""
        try:
            result = subprocess.run(
                ["claude", "-p", prompt, "--output-format", "text"],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=REPO_ROOT
            )

            output = result.stdout.strip()

            # Extract JSON
            import re
            json_match = re.search(r'\{[^{}]*\}', output, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))

            return {"status": "unknown", "raw": output[:500]}

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "timeout"}
        except json.JSONDecodeError as e:
            return {"status": "error", "message": f"JSON error: {e}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def process_next_function(self) -> Dict[str, Any]:
        """Process the next undocumented function."""
        # Get next function
        func = self.loop.get_next_function_to_document()

        if not func:
            return {"status": "none", "message": "No undocumented functions"}

        func_name = func["name"]
        func_addr = func["address"]

        logger.info(f"Processing: {func_name} @ {func_addr}")

        # Mark work started
        self.loop.start_function_work(func_name, func_addr)

        # Run Claude to document
        prompt = DOCUMENT_FUNCTION_PROMPT.format(
            function_name=func_name,
            function_address=func_addr
        )

        result = self.run_claude(prompt)

        if result.get("status") == "success":
            self.consecutive_errors = 0
            self.loop.complete_function_work(func_addr, success=True)

            # Run quality audit on this function
            audit = self.improvement_engine.auditor.audit_function(func_addr, result.get("new_name", func_name))
            result["quality_audit"] = audit

            logger.info(f"Documented: {func_name} -> {result.get('new_name')} (score: {result.get('score')})")
        else:
            self.consecutive_errors += 1
            self.errors_this_session += 1
            self.loop.complete_function_work(func_addr, success=False)

            # Record the error
            self.improvement_engine.record_tool_error(
                "document_function",
                result.get("message", "Unknown error"),
                {"function": func_name, "address": func_addr}
            )

            logger.warning(f"Failed to document {func_name}: {result.get('message')}")

        self.functions_processed += 1
        return result

    def process_issue(self, issue: Dict) -> Dict[str, Any]:
        """Process a specific issue from the work queue."""
        logger.info(f"Processing issue: {issue['issue_id']} - {issue['action']}")

        context_str = ""
        if issue.get("variables"):
            context_str = f"Variables to type: {', '.join(issue['variables'][:10])}"
        elif issue.get("issues"):
            context_str = f"Plate comment issues: {', '.join(issue['issues'][:5])}"

        prompt = REMEDIATE_ISSUE_PROMPT.format(
            issue_type=issue.get("action", "unknown"),
            function_name=issue.get("function", "unknown"),
            function_address=issue.get("address", "unknown"),
            description=issue.get("instruction", "Fix the issue"),
            context=context_str,
            instruction=issue.get("instruction", "")
        )

        result = self.run_claude(prompt, timeout=120)

        if result.get("status") == "fixed":
            # Resolve the issue
            self.improvement_engine.issues.resolve_issue(
                issue["issue_id"],
                result.get("action", "Fixed by Claude")
            )
            logger.info(f"Resolved issue {issue['issue_id']}")
        else:
            logger.warning(f"Could not resolve issue {issue['issue_id']}: {result.get('message')}")

        return result

    def run_improvement_cycle(self) -> Dict[str, Any]:
        """Run a full improvement cycle."""
        logger.info("Running improvement cycle...")

        # First, run the engine's internal cycle
        cycle_result = self.improvement_engine.run_improvement_cycle()

        # Then process any issues that need Claude
        work_queue = self.improvement_engine.get_claude_work_queue()

        issues_processed = 0
        for issue in work_queue[:5]:  # Process up to 5 issues per cycle
            result = self.process_issue(issue)
            if result.get("status") == "fixed":
                issues_processed += 1

        cycle_result["claude_issues_processed"] = issues_processed

        return cycle_result

    def check_health(self) -> bool:
        """Check if we should continue running."""
        # Check consecutive errors
        if self.consecutive_errors >= self.max_consecutive_errors:
            logger.error(f"Too many consecutive errors ({self.consecutive_errors}), stopping")
            return False

        # Check tool health
        health = self.improvement_engine.health.get_health_summary()
        if health.get("overall_status") == "failing":
            logger.error(f"Critical tool failures: {health.get('failing_tools')}")
            return False

        return True

    def run_session(
        self,
        max_functions: int = 50,
        max_hours: float = 4.0,
        process_issues: bool = True
    ) -> Dict[str, Any]:
        """
        Run an autonomous documentation session.

        Args:
            max_functions: Max functions to document
            max_hours: Max session duration
            process_issues: Whether to process remediation issues

        Returns:
            Session summary
        """
        logger.info(f"Starting autonomous session: max_functions={max_functions}, max_hours={max_hours}")

        end_time = datetime.now() + timedelta(hours=max_hours)

        session_results = {
            "start_time": self.session_start.isoformat(),
            "functions_documented": 0,
            "functions_failed": 0,
            "issues_resolved": 0,
            "improvement_cycles": 0
        }

        while self.functions_processed < max_functions and datetime.now() < end_time:
            # Check health
            if not self.check_health():
                break

            # Periodic health check
            if self.functions_processed > 0 and self.functions_processed % self.health_check_interval == 0:
                self.improvement_engine.health.run_health_check()

            # Periodic improvement cycle
            if self.functions_processed > 0 and self.functions_processed % self.improvement_interval == 0:
                cycle_result = self.run_improvement_cycle()
                session_results["improvement_cycles"] += 1
                session_results["issues_resolved"] += cycle_result.get("claude_issues_processed", 0)

            # Process next function
            result = self.process_next_function()

            if result.get("status") == "none":
                logger.info("No more undocumented functions")
                break
            elif result.get("status") == "success":
                session_results["functions_documented"] += 1
            else:
                session_results["functions_failed"] += 1

            # Brief pause
            time.sleep(1)

        # Final improvement cycle
        if self.functions_processed > 0:
            self.run_improvement_cycle()

        session_results["end_time"] = datetime.now().isoformat()
        session_results["total_processed"] = self.functions_processed

        logger.info(f"Session complete: {session_results}")
        return session_results

    def get_status(self) -> Dict[str, Any]:
        """Get current status."""
        return {
            "session": {
                "functions_processed": self.functions_processed,
                "errors": self.errors_this_session,
                "consecutive_errors": self.consecutive_errors,
                "duration": str(datetime.now() - self.session_start)
            },
            "improvement": self.improvement_engine.get_status(),
            "work_queue": len(self.improvement_engine.get_claude_work_queue())
        }


def interactive_mode():
    """Run in interactive mode with Claude Code."""
    print("""
============================================================
 AUTONOMOUS SELF-IMPROVING DOCUMENTATION SYSTEM
============================================================

This system will:
1. Document undocumented functions
2. Track and fix specific quality issues
3. Monitor tool health
4. Propose and implement improvements

Commands:
  document <count>  - Document N functions
  issues            - Show and process open issues
  cycle             - Run improvement cycle
  status            - Show current status
  health            - Check tool health
  quit              - Exit

============================================================
""")

    loop = AutonomousLoop()

    while True:
        try:
            cmd = input("\n> ").strip().lower()

            if not cmd:
                continue

            parts = cmd.split()
            action = parts[0]

            if action == "quit" or action == "exit":
                break

            elif action == "document":
                count = int(parts[1]) if len(parts) > 1 else 5
                result = loop.run_session(max_functions=count, max_hours=1.0)
                print(json.dumps(result, indent=2))

            elif action == "issues":
                queue = loop.improvement_engine.get_claude_work_queue()
                print(f"\nOpen issues requiring attention: {len(queue)}")
                for i, issue in enumerate(queue[:10], 1):
                    print(f"  {i}. [{issue['action']}] {issue['function']} - {issue['instruction'][:50]}")

                if queue:
                    process = input("\nProcess issues? (y/n): ").strip().lower()
                    if process == 'y':
                        for issue in queue[:5]:
                            loop.process_issue(issue)

            elif action == "cycle":
                result = loop.run_improvement_cycle()
                print(json.dumps(result, indent=2))

            elif action == "status":
                status = loop.get_status()
                print(json.dumps(status, indent=2))

            elif action == "health":
                health = loop.improvement_engine.health.run_health_check()
                summary = loop.improvement_engine.health.get_health_summary()
                print(f"\nTool Health: {summary['overall_status'].upper()}")
                print(json.dumps(health, indent=2))

            else:
                print(f"Unknown command: {action}")

        except KeyboardInterrupt:
            print("\nInterrupted")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Self-Improving Documentation Loop"
    )
    parser.add_argument("--mode", choices=["interactive", "batch", "single"],
                       default="interactive", help="Run mode")
    parser.add_argument("--functions", "-n", type=int, default=50,
                       help="Functions to document in batch mode")
    parser.add_argument("--hours", "-t", type=float, default=4.0,
                       help="Max hours for batch mode")
    parser.add_argument("--status", action="store_true", help="Show status")
    parser.add_argument("--improve", action="store_true", help="Run improvement cycle")
    parser.add_argument("--issues", action="store_true", help="Show work queue")

    args = parser.parse_args()

    if args.status:
        loop = AutonomousLoop()
        print(json.dumps(loop.get_status(), indent=2))
        return 0

    if args.improve:
        loop = AutonomousLoop()
        result = loop.run_improvement_cycle()
        print(json.dumps(result, indent=2))
        return 0

    if args.issues:
        engine = SelfImprovementEngine()
        queue = engine.get_claude_work_queue()
        print(json.dumps(queue, indent=2))
        return 0

    if args.mode == "interactive":
        interactive_mode()
    elif args.mode == "batch":
        loop = AutonomousLoop()
        result = loop.run_session(max_functions=args.functions, max_hours=args.hours)
        print(json.dumps(result, indent=2))
    elif args.mode == "single":
        loop = AutonomousLoop()
        result = loop.process_next_function()
        print(json.dumps(result, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
