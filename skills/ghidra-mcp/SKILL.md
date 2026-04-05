---
name: ghidra-mcp
description: Use GhidraMCP to reverse engineer binaries - decompile, analyze, rename functions, and list symbols from Codex.
---

# GhidraMCP for Codex

Reverse engineer binaries through the GhidraMCP server, giving Codex access to Ghidra's core functionality.

## When to use

- Analyzing compiled binaries and firmware
- Decompiling functions to understand program behavior
- Renaming methods and data to improve readability
- Listing classes, imports, exports, and cross-references
- Security research and vulnerability analysis

## Prerequisites

- Ghidra must be installed and running
- The bridge_mcp_ghidra.py script must be accessible
- Python 3 with MCP SDK dependencies installed

## Tips

- Start with listing functions and classes to get an overview
- Use decompilation on specific functions of interest
- The Ghidra GUI stays synchronized with MCP-driven changes
- Combine with web search for identifying known vulnerabilities in discovered functions
