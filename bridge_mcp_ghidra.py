# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2.32,<3",
#     "mcp>=1.30,<2",
# ]
# ///
"""Legacy entry point. Prefer the `ghidra-mcp` command (see README)."""

import os
import sys

try:
    from ghidra_mcp.cli import main
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
    from ghidra_mcp.cli import main

if __name__ == "__main__":
    main()
