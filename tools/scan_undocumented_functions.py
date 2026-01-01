#!/usr/bin/env python3
"""
Batch scan all undocumented functions and rank by xref count.

This script finds all functions matching a pattern (default: FUN_*),
gets their cross-reference counts, and outputs a sorted list.

Usage:
    python scan_undocumented_functions.py [--pattern FUN_] [--limit 1000] [--output results.txt]
"""

import argparse
import requests
import json
import sys
from typing import List, Tuple, Dict
import time

# Ghidra MCP server configuration
GHIDRA_SERVER = "http://127.0.0.1:8089"
REQUEST_TIMEOUT = 10  # seconds


def search_functions(pattern: str, limit: int = 1000) -> List[Dict[str, str]]:
    """
    Search for functions matching a pattern.

    Args:
        pattern: Function name pattern to search for
        limit: Maximum number of results

    Returns:
        List of dicts with 'name' and 'address' keys
    """
    try:
        url = f"{GHIDRA_SERVER}/searchFunctions"
        params = {"query": pattern, "offset": 0, "limit": limit}
        response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)

        if not response.ok:
            print(f"Error searching functions: {response.status_code}", file=sys.stderr)
            return []

        # Parse response - format is "FUN_6fb17070 @ 6fb17070"
        functions = []
        for line in response.text.strip().split('\n'):
            if ' @ ' in line:
                name, address = line.split(' @ ')
                functions.append({'name': name.strip(), 'address': address.strip()})

        return functions

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return []


def get_function_xref_count(function_name: str) -> int:
    """
    Get the number of cross-references to a function.

    Args:
        function_name: Name of the function

    Returns:
        Number of xrefs (0 if error or none found)
    """
    try:
        url = f"{GHIDRA_SERVER}/get_function_xrefs"
        params = {"name": function_name, "limit": 1000}
        response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)

        if not response.ok:
            return 0

        text = response.text.strip()

        # Handle "No references found" message
        if "No references found" in text:
            return 0

        # Count lines (each line is one xref)
        if text:
            return len([line for line in text.split('\n') if line.strip()])

        return 0

    except requests.exceptions.RequestException:
        return 0


def batch_scan_functions(pattern: str = "FUN_", limit: int = 1000,
                         progress: bool = True) -> List[Tuple[str, str, int]]:
    """
    Scan all functions matching pattern and get their xref counts.

    Args:
        pattern: Function name pattern to search for
        limit: Maximum number of functions to scan
        progress: Show progress indicator

    Returns:
        List of tuples: (function_name, address, xref_count)
    """
    print(f"Searching for functions matching '{pattern}'...", file=sys.stderr)
    functions = search_functions(pattern, limit)

    if not functions:
        print("No functions found!", file=sys.stderr)
        return []

    print(f"Found {len(functions)} functions. Getting xref counts...", file=sys.stderr)

    results = []
    total = len(functions)

    for i, func in enumerate(functions, 1):
        if progress and i % 10 == 0:
            print(f"Progress: {i}/{total} ({i*100//total}%)", file=sys.stderr)

        xref_count = get_function_xref_count(func['name'])
        results.append((func['name'], func['address'], xref_count))

        # Small delay to avoid overwhelming the server
        time.sleep(0.05)

    if progress:
        print(f"Progress: {total}/{total} (100%)", file=sys.stderr)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scan undocumented functions and rank by xref count"
    )
    parser.add_argument(
        "--pattern",
        default="FUN_",
        help="Function name pattern to search for (default: FUN_)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum number of functions to scan (default: 1000)"
    )
    parser.add_argument(
        "--output",
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--min-xrefs",
        type=int,
        default=0,
        help="Only show functions with at least this many xrefs (default: 0)"
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress output"
    )
    parser.add_argument(
        "--format",
        choices=["text", "csv", "json"],
        default="text",
        help="Output format (default: text)"
    )

    args = parser.parse_args()

    # Check server connectivity
    try:
        response = requests.get(f"{GHIDRA_SERVER}/check_connection", timeout=5)
        if not response.ok:
            print("Error: Cannot connect to Ghidra MCP server", file=sys.stderr)
            print(f"Make sure Ghidra is running with the plugin on {GHIDRA_SERVER}", file=sys.stderr)
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error: Cannot connect to Ghidra MCP server: {e}", file=sys.stderr)
        sys.exit(1)

    # Scan functions
    results = batch_scan_functions(
        pattern=args.pattern,
        limit=args.limit,
        progress=not args.no_progress
    )

    # Filter by minimum xrefs
    if args.min_xrefs > 0:
        results = [(name, addr, count) for name, addr, count in results
                   if count >= args.min_xrefs]

    # Sort by xref count (descending)
    results.sort(key=lambda x: x[2], reverse=True)

    # Format output
    output_file = open(args.output, 'w') if args.output else sys.stdout

    try:
        if args.format == "json":
            data = [
                {"name": name, "address": addr, "xref_count": count}
                for name, addr, count in results
            ]
            json.dump(data, output_file, indent=2)

        elif args.format == "csv":
            output_file.write("Function Name,Address,Xref Count\n")
            for name, addr, count in results:
                output_file.write(f"{name},{addr},{count}\n")

        else:  # text format
            output_file.write(f"{'Function Name':<30} {'Address':<12} {'Xrefs':<10}\n")
            output_file.write("=" * 52 + "\n")

            for name, addr, count in results:
                output_file.write(f"{name:<30} {addr:<12} {count:<10}\n")

            # Summary statistics
            total_funcs = len(results)
            total_xrefs = sum(count for _, _, count in results)
            avg_xrefs = total_xrefs / total_funcs if total_funcs > 0 else 0

            with_xrefs = sum(1 for _, _, count in results if count > 0)
            without_xrefs = total_funcs - with_xrefs

            output_file.write("\n" + "=" * 52 + "\n")
            output_file.write(f"Total functions: {total_funcs}\n")
            output_file.write(f"Functions with xrefs: {with_xrefs}\n")
            output_file.write(f"Functions without xrefs: {without_xrefs}\n")
            output_file.write(f"Average xrefs per function: {avg_xrefs:.2f}\n")

            if results:
                output_file.write(f"\nHighest xref count: {results[0][2]} ({results[0][0]})\n")

    finally:
        if args.output:
            output_file.close()
            print(f"\nResults written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
