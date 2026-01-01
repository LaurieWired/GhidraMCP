# Tools Directory

Utility scripts and tools for the Ghidra MCP Server project.

## 📦 Available Tools

### Function Documentation Tools

#### `document_function.py`
**Purpose**: Automated function documentation using MCP tools

**Description**: Standalone script for documenting individual functions in Ghidra using the MCP API. Analyzes function context, generates meaningful names, and applies comprehensive documentation.

**Usage**:
```bash
python tools/document_function.py
```

**Features**:
- Decompilation analysis
- Cross-reference analysis
- Automated naming suggestions
- Variable type inference
- Comment generation
- Label creation

---

#### `scan_functions_mcp.py`
**Purpose**: Batch function scanning and analysis

**Description**: Scans multiple functions in a Ghidra project, identifying candidates for documentation based on cross-reference counts, complexity, and other metrics.

**Usage**:
```bash
python tools/scan_functions_mcp.py
```

**Features**:
- Multi-function scanning
- Priority ranking by xrefs
- Pattern-based filtering
- Export results to JSON/CSV
- Integration with function documentation workflow

---

#### `scan_undocumented_functions.py`
**Purpose**: Find undocumented functions (FUN_ pattern)

**Description**: Identifies functions that need documentation by detecting default Ghidra naming patterns (FUN_*). Prioritizes by importance metrics.

**Usage**:
```bash
python tools/scan_undocumented_functions.py
```

**Features**:
- Automated FUN_ detection
- Cross-reference counting
- Complexity metrics
- Sorted output by priority
- Integration with search_functions_enhanced

---

## 🔧 Requirements

All tools require:
- Python 3.8+
- Ghidra MCP Server running (port 8089)
- Binary loaded in Ghidra CodeBrowser
- Python dependencies from `requirements.txt`

## 🚀 Workflow Integration

### Typical Documentation Workflow

1. **Scan for candidates**:
   ```bash
   python tools/scan_undocumented_functions.py > undocumented.txt
   ```

2. **Analyze specific functions**:
   ```bash
   python tools/scan_functions_mcp.py --pattern "FUN_" --min-xrefs 2
   ```

3. **Document functions**:
   ```bash
   python tools/document_function.py --function FUN_401000
   ```

### Batch Processing Example

```bash
# Find top 20 undocumented functions by xref count
python tools/scan_undocumented_functions.py --limit 20 --sort-by xrefs

# Document each function
for func in $(cat undocumented.txt); do
    python tools/document_function.py --function $func
done
```

## 📚 Related Documentation

- **[API Reference](../docs/API_REFERENCE.md)** - MCP tools used by these scripts
- **[Unified Analysis Prompt](../docs/prompts/UNIFIED_ANALYSIS_PROMPT.md)** - Manual workflow
- **[Development Guide](../docs/DEVELOPMENT_GUIDE.md)** - Contributing guidelines

## 🤝 Contributing

To add new tools to this directory:

1. Create standalone Python script
2. Add docstring with purpose and usage
3. Update this README with tool documentation
4. Test with Ghidra MCP Server
5. Submit pull request

## 📝 Tool Template

```python
#!/usr/bin/env python3
"""
Tool Name - Brief Description

Purpose: Detailed purpose of the tool
Usage: python tools/tool_name.py [options]
"""

import sys
import requests

# Tool implementation
if __name__ == "__main__":
    # Entry point
    pass
```

---

**Note**: All tools connect to Ghidra MCP Server via HTTP (default: http://127.0.0.1:8089)
