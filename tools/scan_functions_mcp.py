#!/usr/bin/env python3
"""
Scan undocumented functions using Ghidra REST API.

This script queries Ghidra directly to find and rank functions by xref count.

Usage:
    python scan_functions_mcp.py [--pattern FUN_] [--limit 50] [--min-xrefs 2]
"""

import argparse
import json
import sys
import requests

GHIDRA_SERVER = "http://127.0.0.1:8089"


def scan_functions(pattern: str = "FUN_", limit: int = 50, min_xrefs: int = 0):
    """
    Scan functions matching pattern and rank by xref count.

    Args:
        pattern: Function name pattern to search
        limit: Maximum functions to scan
        min_xrefs: Minimum xrefs to include in results

    Returns:
        List of tuples: (name, address, xref_count)
    """
    print(f"Searching for functions matching '{pattern}'...", file=sys.stderr)

    # Search for functions
    try:
        response = requests.get(f"{GHIDRA_SERVER}/searchFunctions", params={"query": pattern, "limit": limit})
        response.raise_for_status()
        search_result = response.text

        # Parse result - format is "FUN_6fb17070 @ 6fb17070"
        functions = []
        for line in search_result.split('\n'):
            if ' @ ' in line:
                name, address = line.split(' @ ')
                functions.append({'name': name.strip(), 'address': address.strip()})
    except Exception as e:
        print(f"Error searching functions: {e}", file=sys.stderr)
        return []

    if not functions:
        print("No functions found!", file=sys.stderr)
        return []

    print(f"Found {len(functions)} functions. Getting xref counts...", file=sys.stderr)

    results = []
    for i, func in enumerate(functions, 1):
        if i % 10 == 0:
            print(f"Progress: {i}/{len(functions)} ({i*100//len(functions)}%)", file=sys.stderr)

        try:
            response = requests.get(f"{GHIDRA_SERVER}/function_xrefs", params={"name": func['name'], "limit": 1000})
            response.raise_for_status()
            xref_result = response.text

            # Count xrefs
            if "No references found" in xref_result:
                xref_count = 0
            else:
                xref_count = len([line for line in xref_result.split('\n') if line.strip()])

            if xref_count >= min_xrefs:
                results.append((func['name'], func['address'], xref_count))

        except Exception as e:
            print(f"Error getting xrefs for {func['name']}: {e}", file=sys.stderr)
            results.append((func['name'], func['address'], 0))

    print(f"Progress: {len(functions)}/{len(functions)} (100%)", file=sys.stderr)

    # Sort by xref count descending
    results.sort(key=lambda x: x[2], reverse=True)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scan undocumented functions and rank by xref count"
    )
    parser.add_argument(
        "--pattern",
        default="FUN_",
        help="Function name pattern (default: FUN_)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max functions to scan (default: 50)"
    )
    parser.add_argument(
        "--min-xrefs",
        type=int,
        default=0,
        help="Min xrefs to show (default: 0)"
    )
    parser.add_argument(
        "--output",
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--format",
        choices=["text", "csv", "json"],
        default="text",
        help="Output format (default: text)"
    )

    args = parser.parse_args()

    # Scan functions
    results = scan_functions(args.pattern, args.limit, args.min_xrefs)

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

        else:  # text
            output_file.write(f"{'Function Name':<30} {'Address':<12} {'Xrefs':<10}\n")
            output_file.write("=" * 52 + "\n")

            for name, addr, count in results:
                output_file.write(f"{name:<30} {addr:<12} {count:<10}\n")

            # Summary
            if results:
                total = len(results)
                total_xrefs = sum(count for _, _, count in results)
                avg_xrefs = total_xrefs / total if total > 0 else 0

                output_file.write("\n" + "=" * 52 + "\n")
                output_file.write(f"Total functions: {total}\n")
                output_file.write(f"Average xrefs: {avg_xrefs:.2f}\n")
                output_file.write(f"Highest xref count: {results[0][2]} ({results[0][0]})\n")

    finally:
        if args.output:
            output_file.close()
            print(f"\nResults written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
