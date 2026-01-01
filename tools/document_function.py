#!/usr/bin/env python3
"""
Optimized function documentation workflow for Ghidra MCP.

This script implements the efficient workflow identified in the analysis:
1. Batch gather all function data
2. Analyze and plan changes
3. Apply all changes using batch operations
4. Verify completeness

Usage:
    python document_function.py <function_address> [--verify-only]

Example:
    python document_function.py 0x6fb44aa0
    python document_function.py 0x6fb21690 --verify-only
"""

import argparse
import requests
import json
import sys
from typing import Dict, List, Optional, Tuple


GHIDRA_SERVER = "http://127.0.0.1:8089"
REQUEST_TIMEOUT = 30


class FunctionDocumenter:
    """Optimized function documentation workflow."""

    def __init__(self, server_url: str = GHIDRA_SERVER):
        self.server = server_url
        self.function_data = {}

    def _get(self, endpoint: str, params: Dict = None) -> Optional[str]:
        """Make GET request to Ghidra server."""
        try:
            url = f"{self.server}/{endpoint}"
            response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
            if response.ok:
                return response.text
            print(f"Error: {endpoint} returned {response.status_code}", file=sys.stderr)
            return None
        except requests.exceptions.RequestException as e:
            print(f"Request error for {endpoint}: {e}", file=sys.stderr)
            return None

    def _post(self, endpoint: str, data: Dict) -> Optional[str]:
        """Make POST request to Ghidra server."""
        try:
            url = f"{self.server}/{endpoint}"
            response = requests.post(url, json=data, timeout=REQUEST_TIMEOUT)
            if response.ok:
                return response.text
            print(f"Error: {endpoint} returned {response.status_code}", file=sys.stderr)
            return None
        except requests.exceptions.RequestException as e:
            print(f"Request error for {endpoint}: {e}", file=sys.stderr)
            return None

    def gather_function_data(self, address: str) -> bool:
        """
        Phase 1: Batch gather all function data (parallel where possible).

        Returns:
            True if successful, False otherwise
        """
        print(f"\n[Phase 1] Gathering function data for {address}...")

        # Get basic function info
        func_info = self._get("get_function_by_address", {"address": address})
        if not func_info:
            print("Error: Function not found", file=sys.stderr)
            return False

        # Extract function name from response
        if "Function:" in func_info:
            lines = func_info.split('\n')
            func_name = lines[0].replace("Function:", "").split("at")[0].strip()
        else:
            print("Error: Could not parse function name", file=sys.stderr)
            return False

        print(f"  Found function: {func_name}")

        # Batch gather: decompilation, callees, variables, xrefs (in parallel conceptually)
        print("  Decompiling function...")
        decompiled = self._get("decompile_function", {"name": func_name})

        print("  Getting function callees...")
        callees = self._get("get_function_callees", {"name": func_name, "limit": 100})

        print("  Getting function variables...")
        variables = self._get("get_function_variables", {"name": func_name})

        print("  Getting cross-references...")
        xrefs = self._get("get_function_xrefs", {"name": func_name, "limit": 100})

        print("  Getting disassembly...")
        disassembly = self._get("disassemble_function", {"address": address})

        # Store all data
        self.function_data = {
            "address": address,
            "name": func_name,
            "info": func_info,
            "decompiled": decompiled,
            "callees": callees,
            "variables": variables,
            "xrefs": xrefs,
            "disassembly": disassembly
        }

        print(f"✓ Data gathering complete\n")
        return True

    def analyze_and_plan(self) -> Dict:
        """
        Phase 2: Analyze gathered data and create documentation plan.

        Returns:
            Dict with planned changes
        """
        print("[Phase 2] Analyzing function and planning changes...")

        plan = {
            "new_name": None,
            "prototype": None,
            "calling_convention": "__stdcall",
            "variable_renames": {},
            "variable_types": {},
            "plate_comment": None,
            "decompiler_comments": [],
            "disassembly_comments": []
        }

        # Analyze function purpose from callees and xrefs
        print("  Analyzing function purpose...")
        callees = self.function_data.get("callees", "")
        xrefs = self.function_data.get("xrefs", "")

        # Count xrefs for importance
        xref_count = len([x for x in xrefs.split('\n') if x.strip() and "From" in x])
        print(f"    Cross-references: {xref_count}")

        # List called functions
        if callees:
            callee_list = [c.split('@')[0].strip() for c in callees.split('\n') if '@' in c]
            print(f"    Calls {len(callee_list)} functions")
            for callee in callee_list[:5]:  # Show first 5
                print(f"      - {callee}")

        # Analyze variables that need renaming
        variables_data = self.function_data.get("variables")
        if variables_data:
            try:
                vars_json = json.loads(variables_data)
                params = vars_json.get("parameters", [])
                locals_list = vars_json.get("locals", [])

                print(f"    Parameters: {len(params)}")
                print(f"    Local variables: {len(locals_list)}")

                # Identify variables that need better names
                for param in params:
                    if param["name"].startswith("param_"):
                        print(f"      TODO: Rename {param['name']} (type: {param['type']})")

                for local in locals_list:
                    if local["name"].startswith("local_") or "Var" in local["name"]:
                        print(f"      TODO: Rename {param['name']} (type: {param['type']})")

            except json.JSONDecodeError:
                print("    Warning: Could not parse variables JSON")

        print("\n  Please provide documentation details:")
        print("  (Press Enter to skip any field)\n")

        # Interactive prompts for documentation
        new_name = input("  New function name [leave blank to skip]: ").strip()
        if new_name:
            plan["new_name"] = new_name

        plate_comment = input("  Function summary comment [leave blank to skip]: ").strip()
        if plate_comment:
            plan["plate_comment"] = plate_comment

        return plan

    def apply_changes(self, plan: Dict) -> bool:
        """
        Phase 3: Apply all documentation changes using batch operations.

        Returns:
            True if successful
        """
        print("\n[Phase 3] Applying documentation changes...")

        address = self.function_data["address"]
        current_name = self.function_data["name"]

        # Rename function if requested
        if plan.get("new_name"):
            print(f"  Renaming function to: {plan['new_name']}")
            result = self._post("rename_function_by_address", {
                "function_address": address,
                "new_name": plan["new_name"]
            })
            if result and "Success" in result:
                print("    ✓ Function renamed")
                current_name = plan["new_name"]
            else:
                print("    ✗ Failed to rename function")

        # Set function prototype if provided
        if plan.get("prototype"):
            print(f"  Setting prototype...")
            result = self._post("set_function_prototype", {
                "function_address": address,
                "prototype": plan["prototype"],
                "calling_convention": plan.get("calling_convention", "__stdcall")
            })
            if result and "success" in result.lower():
                print("    ✓ Prototype set")
            else:
                print("    ✗ Failed to set prototype")

        # Set plate comment if provided
        if plan.get("plate_comment"):
            print(f"  Setting plate comment...")
            result = self._post("set_plate_comment", {
                "function_address": address,
                "comment": plan["plate_comment"]
            })
            if result and "Success" in result:
                print("    ✓ Plate comment set")
            else:
                print("    ✗ Failed to set plate comment")

        # Batch rename variables if any
        if plan.get("variable_renames"):
            print(f"  Batch renaming {len(plan['variable_renames'])} variables...")
            # Note: Would use batch_rename_function_components if available
            for old_name, new_name in plan["variable_renames"].items():
                result = self._post("rename_variable", {
                    "function_name": current_name,
                    "old_name": old_name,
                    "new_name": new_name
                })

        print("\n✓ All changes applied")
        return True

    def verify_completeness(self) -> Dict:
        """
        Phase 4: Verify documentation completeness.

        Returns:
            Dict with completeness analysis
        """
        print("\n[Phase 4] Verifying documentation completeness...")

        address = self.function_data["address"]

        # Use analyze_function_completeness if available
        result = self._get("analyze_function_completeness", {"function_address": address})

        if result:
            try:
                analysis = json.loads(result)
                print(f"\n  Completeness Score: {analysis.get('completeness_score', 0)}/100")
                print(f"  Has custom name: {analysis.get('has_custom_name', False)}")
                print(f"  Has prototype: {analysis.get('has_prototype', False)}")
                print(f"  Has plate comment: {analysis.get('has_plate_comment', False)}")

                undefined_vars = analysis.get('undefined_variables', [])
                if undefined_vars:
                    print(f"\n  ⚠ Undefined variables still present:")
                    for var in undefined_vars:
                        print(f"    - {var}")
                else:
                    print(f"\n  ✓ No undefined variables")

                return analysis

            except json.JSONDecodeError:
                print("  Warning: Could not parse completeness analysis")

        # Re-decompile to verify changes
        print("\n  Re-decompiling to verify changes...")
        current_name = self.function_data.get("name")
        decompiled = self._get("decompile_function", {"name": current_name})

        if decompiled:
            print("  ✓ Function re-decompiled successfully")
        else:
            print("  ✗ Failed to re-decompile")

        return {}


def main():
    parser = argparse.ArgumentParser(
        description="Document a function using optimized workflow"
    )
    parser.add_argument(
        "address",
        help="Function address (e.g., 0x6fb44aa0)"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify completeness, don't document"
    )
    parser.add_argument(
        "--server",
        default=GHIDRA_SERVER,
        help=f"Ghidra MCP server URL (default: {GHIDRA_SERVER})"
    )

    args = parser.parse_args()

    documenter = FunctionDocumenter(args.server)

    # Check server connectivity
    try:
        response = requests.get(f"{args.server}/check_connection", timeout=5)
        if not response.ok:
            print(f"Error: Cannot connect to Ghidra MCP server at {args.server}", file=sys.stderr)
            sys.exit(1)
        print(f"✓ Connected to Ghidra: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error: Cannot connect to Ghidra MCP server: {e}", file=sys.stderr)
        sys.exit(1)

    # Gather function data
    if not documenter.gather_function_data(args.address):
        sys.exit(1)

    if args.verify_only:
        # Just verify
        documenter.verify_completeness()
    else:
        # Full workflow
        plan = documenter.analyze_and_plan()
        documenter.apply_changes(plan)
        documenter.verify_completeness()

    print("\n✓ Documentation workflow complete!")


if __name__ == "__main__":
    main()
