#!/usr/bin/env python3
"""
Autonomous Runner for Continuous Improvement

This script runs Claude Code in a loop, feeding it documentation tasks
and collecting results. It provides the "outer loop" for fully automated
self-improvement.

Usage:
    python autonomous_runner.py --max-functions 100 --session-hours 4

Requirements:
    - Claude Code CLI installed (`claude` command available)
    - Ghidra running with MCP plugin
    - ANTHROPIC_API_KEY set (for Claude Code)

Architecture:
    This script -> Claude Code (subprocess) -> MCP -> Ghidra
"""

import subprocess
import json
import time
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta
import logging

# Setup logging
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"autonomous_{datetime.now():%Y%m%d_%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Prompts for Claude Code
DOCUMENT_PROMPT = """Document the next undocumented function in Ghidra:

1. Use find_next_undefined_function to find a FUN_* function
2. Decompile it and gather context (callees, callers, variables)
3. Analyze the code and determine:
   - Appropriate PascalCase name based on purpose
   - Parameter and return types
   - Variable types with Hungarian notation
   - Brief plate comment (3-5 lines)
4. Apply documentation using batch operations
5. Verify with analyze_function_completeness
6. Output ONLY a JSON result:
   {"status": "success", "old_name": "FUN_XXX", "new_name": "Name", "score": 85}
   or {"status": "error", "message": "reason"}
   or {"status": "none", "message": "no undocumented functions"}
"""

IMPROVE_TOOLING_PROMPT = """Review recent friction points and propose tool improvements:

1. Check the friction history in the improvement state
2. Identify patterns in what's causing issues
3. If a tool improvement would help, propose it
4. Output a JSON result:
   {"status": "proposed", "tool": "name", "description": "what to add"}
   or {"status": "none", "message": "no improvements needed"}
"""


def run_claude_code(prompt: str, timeout: int = 300) -> dict:
    """
    Run Claude Code with a prompt and parse the result.

    Args:
        prompt: The prompt to send to Claude Code
        timeout: Timeout in seconds

    Returns:
        Parsed JSON result or error dict
    """
    try:
        # Run claude with the prompt
        result = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=Path(__file__).parent.parent  # Project root
        )

        output = result.stdout.strip()

        # Try to extract JSON from the output
        # Claude might wrap it in markdown or have extra text
        import re
        json_match = re.search(r'\{[^{}]*"status"[^{}]*\}', output, re.DOTALL)

        if json_match:
            return json.loads(json_match.group(0))
        else:
            # Return raw output as message
            return {"status": "unknown", "raw_output": output[:500]}

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "timeout"}
    except json.JSONDecodeError as e:
        return {"status": "error", "message": f"JSON parse error: {e}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_ghidra_available() -> bool:
    """Check if Ghidra MCP is accessible."""
    try:
        import requests
        response = requests.get("http://127.0.0.1:8089/methods", timeout=5)
        return response.status_code == 200
    except Exception:
        return False


def run_autonomous_session(
    max_functions: int = 50,
    max_hours: float = 4.0,
    improvement_interval: int = 10,
    pause_between: float = 2.0
):
    """
    Run an autonomous documentation and improvement session.

    Args:
        max_functions: Maximum functions to document
        max_hours: Maximum session duration in hours
        improvement_interval: Check for tool improvements every N functions
        pause_between: Seconds to pause between operations
    """
    logger.info(f"Starting autonomous session: max_functions={max_functions}, max_hours={max_hours}")

    start_time = datetime.now()
    end_time = start_time + timedelta(hours=max_hours)

    stats = {
        "functions_documented": 0,
        "functions_failed": 0,
        "improvements_proposed": 0,
        "errors": 0
    }

    # Check Ghidra
    if not check_ghidra_available():
        logger.error("Ghidra MCP not available. Start Ghidra with MCP plugin first.")
        return stats

    logger.info("Ghidra MCP connected. Starting documentation loop...")

    function_count = 0

    while function_count < max_functions and datetime.now() < end_time:
        # Document next function
        logger.info(f"[{function_count + 1}/{max_functions}] Documenting next function...")

        result = run_claude_code(DOCUMENT_PROMPT)

        if result.get("status") == "success":
            stats["functions_documented"] += 1
            logger.info(f"  Documented: {result.get('old_name')} -> {result.get('new_name')} "
                       f"(score: {result.get('score')})")
        elif result.get("status") == "none":
            logger.info("  No more undocumented functions. Session complete!")
            break
        elif result.get("status") == "error":
            stats["functions_failed"] += 1
            stats["errors"] += 1
            logger.warning(f"  Error: {result.get('message')}")
        else:
            logger.warning(f"  Unexpected result: {result}")

        function_count += 1

        # Periodically check for tool improvements
        if function_count % improvement_interval == 0:
            logger.info("Checking for tool improvements...")
            improvement = run_claude_code(IMPROVE_TOOLING_PROMPT, timeout=120)

            if improvement.get("status") == "proposed":
                stats["improvements_proposed"] += 1
                logger.info(f"  Tool improvement proposed: {improvement.get('description')}")

        # Pause to avoid overwhelming the system
        time.sleep(pause_between)

        # Re-check Ghidra connection periodically
        if function_count % 5 == 0:
            if not check_ghidra_available():
                logger.warning("Lost connection to Ghidra. Waiting for reconnect...")
                for _ in range(12):  # Wait up to 60 seconds
                    time.sleep(5)
                    if check_ghidra_available():
                        logger.info("Reconnected to Ghidra")
                        break
                else:
                    logger.error("Could not reconnect to Ghidra. Ending session.")
                    break

    # Session summary
    duration = datetime.now() - start_time
    logger.info("=" * 60)
    logger.info("SESSION COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Duration: {duration}")
    logger.info(f"Functions documented: {stats['functions_documented']}")
    logger.info(f"Functions failed: {stats['functions_failed']}")
    logger.info(f"Tool improvements proposed: {stats['improvements_proposed']}")
    logger.info(f"Total errors: {stats['errors']}")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Runner for Continuous Improvement"
    )
    parser.add_argument(
        "--max-functions", "-n",
        type=int,
        default=50,
        help="Maximum functions to document (default: 50)"
    )
    parser.add_argument(
        "--max-hours", "-t",
        type=float,
        default=4.0,
        help="Maximum session duration in hours (default: 4)"
    )
    parser.add_argument(
        "--improvement-interval", "-i",
        type=int,
        default=10,
        help="Check for tool improvements every N functions (default: 10)"
    )
    parser.add_argument(
        "--pause", "-p",
        type=float,
        default=2.0,
        help="Seconds to pause between operations (default: 2)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Just check if Ghidra is available"
    )

    args = parser.parse_args()

    if args.check:
        available = check_ghidra_available()
        print(f"Ghidra MCP: {'AVAILABLE' if available else 'NOT AVAILABLE'}")
        return 0 if available else 1

    stats = run_autonomous_session(
        max_functions=args.max_functions,
        max_hours=args.max_hours,
        improvement_interval=args.improvement_interval,
        pause_between=args.pause
    )

    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
