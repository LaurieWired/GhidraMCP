# Ghidra MCP Project Structure

> **Organization Guide** - Complete directory structure and file categorization for the Ghidra MCP project.

---

## 📁 Directory Overview

```
ghidra-mcp/
├── 📄 Core Files (Root)
│   ├── bridge_mcp_ghidra.py          # Main MCP server entry point
│   ├── mcp-config.json                # MCP server configuration
│   ├── pom.xml                        # Maven build configuration
│   ├── requirements.txt               # Python dependencies
│   ├── requirements-test.txt          # Test dependencies
│   ├── pytest.ini                     # Pytest configuration
│   └── README.md                      # Project overview
│
├── 🔨 Build & Deployment (Root)
│   ├── deploy-to-ghidra.ps1          # Deploy plugin to Ghidra
│   ├── copy-ghidra-libs.bat          # Copy Ghidra libraries
│   ├── clean-install.ps1             # Clean installation script
│   └── cleanup.ps1                   # Cleanup build artifacts
│
├── 📊 Analysis & Data Files (Root)
│   ├── game.json                     # Game executable analysis data
│   ├── game_minify.json              # Minified game data
│   ├── dll_exports.json              # DLL export mappings
│   ├── dll_exports.txt               # Text format DLL exports
│   ├── process_whitelist.json        # Processing whitelist
│   └── ghidra-custom-d2call-convention.xml  # Custom calling convention
│
├── 📚 Documentation (Root - Organization)
│   ├── START_HERE.md                 # Quick start guide
│   ├── README.md                     # Project overview
│   ├── DOCUMENTATION_INDEX.md        # Master documentation index
│   ├── CHANGELOG.md                  # Version history
│   ├── CONTRIBUTING.md               # Contribution guidelines
│   ├── LICENSE                       # Project license
│   ├── CLAUDE.md                     # Claude AI integration guide
│   ├── NAMING_CONVENTIONS.md         # Naming standards
│   ├── IMPROVEMENTS.md               # Project improvements log
│   ├── IMPROVEMENTS_QUICK_REFERENCE.md  # Quick reference
│   ├── MCP_TOOLS_IMPROVEMENTS.md     # MCP tools changelog
│   ├── GAME_EXE_IMPROVEMENTS.md      # Game.exe analysis improvements
│   └── MAVEN_VERSION_MANAGEMENT.md   # Maven versioning guide
│
├── 📂 docs/ - Comprehensive Documentation
│   ├── 📖 API & Reference
│   │   ├── API_REFERENCE.md          # Complete API documentation
│   │   ├── TOOL_REFERENCE.md         # Tool usage reference
│   │   ├── GHIDRA_MCP_TOOLS_REFERENCE.md  # MCP tools catalog
│   │   ├── ERROR_CODES.md            # Error code reference
│   │   └── DATA_TYPE_TOOLS.md        # Data type tool guide
│   │
│   ├── 📘 Guides
│   │   ├── DEVELOPMENT_GUIDE.md      # Development workflow
│   │   ├── HYBRID_PROCESSOR_GUIDE.md # Hybrid processing guide
│   │   ├── D2_BINARY_ANALYSIS_INTEGRATION_GUIDE.md
│   │   └── D2_CONVENTION_SCRIPTS_README.md
│   │
│   ├── 🔬 Analysis
│   │   └── GAME_EXE_BINARY_ANALYSIS.md  # Complete binary analysis
│   │
│   ├── 🎯 Strategy & Planning
│   │   ├── AGENT_ITERATION_STRATEGIES.md
│   │   └── PERFORMANCE_BASELINES.md
│   │
│   ├── 📝 Conventions
│   │   └── (Naming and coding standards)
│   │
│   ├── 🧪 Testing
│   │   └── (Test documentation and guides)
│   │
│   ├── 🛠️ Troubleshooting
│   │   └── (Common issues and solutions)
│   │
│   ├── 📋 Reports
│   │   ├── PROJECT_CLEANUP_SUMMARY.md
│   │   ├── QUICKWIN_COMPLETION_REPORT.md
│   │   ├── SESSION_SUMMARY_BINARY_ANALYSIS.md
│   │   ├── VERSION_FIX_COMPLETE.md
│   │   ├── VERSION_MANAGEMENT_COMPLETE.md
│   │   └── CLEANUP_FINAL_REPORT.md
│   │
│   └── 🗄️ archive/
│       └── (Historical documentation)
│
├── 🛠️ scripts/ - Automation & Utilities
│   ├── 🔄 Data Processing
│   │   ├── data-extract.ps1          # Extract data from Ghidra
│   │   ├── data-process.ps1          # Process extracted data
│   │   ├── process_char_arrays.py    # Character array processing
│   │   └── make_data_meaningful.py   # Data naming automation
│   │
│   ├── ⚡ Function Processing
│   │   ├── functions-extract.ps1     # Extract function data
│   │   ├── functions-process.ps1     # Process functions
│   │   ├── hybrid-function-processor.ps1  # Hybrid processing
│   │   └── FunctionsTodo.txt         # Function processing tasks
│   │
│   ├── 🧪 Testing & Validation
│   │   ├── test_convention_detection.py
│   │   ├── test_d2_detection.py
│   │   ├── test_d2_simple.py
│   │   ├── test_data_xrefs_tool.py
│   │   ├── validate_function_accuracy.py
│   │   ├── verify_all_structures.py
│   │   ├── quick_detection_test.py
│   │   ├── ghidra_rest_api_functional_tests.py
│   │   ├── ghidra_server_health_check.py
│   │   └── ghidra_plugin_deployment_verifier.py
│   │
│   ├── 🔧 Fix & Repair
│   │   ├── fix_undefined_types.py
│   │   ├── apply_edge_case_fixes.py
│   │   ├── apply_test_fixes.py
│   │   ├── automated_edge_case_fix.py
│   │   ├── run_edge_case_validation.py
│   │   └── ClearCallReturnOverrides.java
│   │
│   ├── 📊 Reporting & Analysis
│   │   ├── final_comprehensive_report.py
│   │   ├── ghidra_mcp_usage_examples.py
│   │   └── search_punit_references.py
│   │
│   ├── 🔍 Verification
│   │   └── verify_version.py
│   │
│   ├── 📝 Configuration
│   │   ├── scripts_config.py
│   │   ├── process_whitelist.json
│   │   └── TEST_SUITE_README.md
│   │
│   └── 📖 Documentation
│       ├── README.md
│       └── CONFIGURATION_MIGRATION_GUIDE.md
│
├── 🔧 tools/ - Specialized Utilities (Root Level)
│   ├── 🎯 Ordinal Link Management
│   │   ├── ordinal_linkage_manager.py    # Main ordinal manager
│   │   ├── ordinal_function_mapping.py   # Function mapping
│   │   ├── ordinal_auto_fixer.py         # Automatic fixing
│   │   ├── export_dll_functions.py       # Export DLL functions
│   │   ├── extract_external_function_pointers.py
│   │   ├── generate_ordinal_mapping.py   # Generate mappings
│   │   ├── list_import_pointers.py       # List imports
│   │   └── process_all_dlls.py           # Batch DLL processing
│   │
│   ├── 🔍 Analysis & Processing
│   │   ├── mcp_function_processor.py     # Function processing
│   │   ├── memory_dumper.py              # Memory dumping
│   │   └── Dump-ProcessMemory.ps1        # PowerShell memory dump
│   │
│   ├── 🧪 Testing & Validation
│   │   ├── test_single_dll.py            # Single DLL testing
│   │   ├── test_improvements.py          # Test improvements
│   │   ├── validate_d2net.py             # D2Net validation
│   │   ├── test_d2net_fix.ps1            # D2Net fix testing
│   │   ├── run_fix_and_validate.ps1      # Fix & validate
│   │   ├── execute_and_validate.ps1      # Execute & validate
│   │   ├── run_headless_fix.py           # Headless fix runner
│   │   └── fix_test_functions.py         # Test function fixes
│   │
│   └── 📄 tools/ subdirectory
│       ├── document_function.py          # Function documentation
│       ├── scan_undocumented_functions.py
│       └── scan_functions_mcp.py
│
├── 🧩 src/ - Java Source Code
│   └── main/java/com/github/ghidramcp/
│       └── (Ghidra plugin source code)
│
├── 🧪 tests/ - Python Test Suite
│   ├── test_enhanced_mcp.py
│   ├── test_complete_system.py
│   ├── test_claude_simple.py
│   ├── test_http_struct_tools.py
│   ├── test_enhanced_prompt_tools.py
│   └── test_mcp_category_tools.py
│
├── 🎮 ghidra_scripts/ - Ghidra Scripts
│   └── (Java scripts for Ghidra automation)
│
├── 💡 examples/ - Usage Examples
│   └── (Example code and demonstrations)
│
├── 📦 lib/ - External Libraries
│   └── (Third-party dependencies)
│
├── 📂 dll_exports/ - DLL Export Data
│   └── (Exported function lists per DLL)
│
├── 📊 logs/ - Runtime Logs
│   └── (Application and test logs)
│
├── 🏗️ target/ - Build Artifacts
│   └── (Maven build output)
│
└── 🖼️ images/ - Documentation Assets
    └── (Screenshots and diagrams)
```

---

## 📋 File Categories

### Core Application Files (Keep in Root)
Essential files that define the project and should remain at root level:
- `bridge_mcp_ghidra.py` - Main MCP server
- `pom.xml` - Maven configuration
- `requirements*.txt` - Dependencies
- `mcp-config.json` - Server config
- `README.md`, `LICENSE`, `START_HERE.md`

### Build & Deployment (Keep in Root)
Scripts frequently used during development:
- `deploy-to-ghidra.ps1`
- `copy-ghidra-libs.bat`
- `clean-install.ps1`
- `cleanup.ps1`

### Data Files (Keep in Root)
Frequently accessed analysis data:
- `game.json`, `game_minify.json`
- `dll_exports.json`, `dll_exports.txt`
- `process_whitelist.json`
- `ghidra-custom-d2call-convention.xml`

### Documentation (Organized in Root + docs/)
- **Root level**: Organization and quick-start docs
- **docs/**: Comprehensive guides, references, and reports

### Scripts (scripts/ directory)
Organized by function:
- Data extraction/processing
- Function analysis
- Testing and validation
- Fix/repair utilities
- Configuration and reporting

### Tools (Root level + tools/ subdirectory)
Specialized utilities for:
- Ordinal linkage management
- DLL analysis
- Memory operations
- Validation workflows

---

## 🔄 Proposed Reorganization

### Phase 1: Move Root-Level Scripts

**To scripts/ordinal-tools/**:
```
ordinal_linkage_manager.py
ordinal_function_mapping.py
ordinal_auto_fixer.py
export_dll_functions.py
extract_external_function_pointers.py
generate_ordinal_mapping.py
list_import_pointers.py
process_all_dlls.py
```

**To scripts/testing/**:
```
test_single_dll.py
test_improvements.py
validate_d2net.py
fix_test_functions.py
```

**To scripts/validation/**:
```
test_d2net_fix.ps1
run_fix_and_validate.ps1
execute_and_validate.ps1
run_headless_fix.py
```

**To scripts/utilities/**:
```
mcp_function_processor.py
memory_dumper.py
Dump-ProcessMemory.ps1
```

### Phase 2: Consolidate Documentation

**Move to docs/reports/**:
```
PROJECT_CLEANUP_SUMMARY.md
QUICKWIN_COMPLETION_REPORT.md
SESSION_SUMMARY_BINARY_ANALYSIS.md
VERSION_FIX_COMPLETE.md
VERSION_MANAGEMENT_COMPLETE.md
VERSION_MANAGEMENT_STRATEGY.md
CLEANUP_FINAL_REPORT.md
STRUCTURE_SUMMARY.txt
```

**Keep in Root** (frequently referenced):
```
START_HERE.md
README.md
CHANGELOG.md
CONTRIBUTING.md
DOCUMENTATION_INDEX.md
CLAUDE.md
NAMING_CONVENTIONS.md
```

### Phase 3: Update References

After moving files:
1. Update import statements in Python scripts
2. Update path references in PowerShell scripts
3. Update documentation links
4. Update VSCode tasks.json paths
5. Update .gitignore patterns

---

### 📝 Usage Guidelines

### When Adding New Files:

1. **Scripts for automation** → `scripts/` (categorized by purpose)
2. **Specialized tools** → Keep in root or `tools/` subdirectory
3. **Documentation** → `docs/` (by category) or root (if frequently accessed)
4. **Test files** → `tests/` (Python) or `scripts/testing/` (validation scripts)
5. **Configuration** → Root level for project-wide, `scripts/` for script-specific
6. **Data files** → Root level for frequently accessed, `dll_exports/` for DLL data

**Naming Standards**:
- Follow [MARKDOWN_NAMING.md](MARKDOWN_NAMING.md) for documentation files
- Use kebab-case for markdown: `getting-started.md`, `api-reference.md`
- Reserve UPPERCASE only for: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `LICENSE`
- See [.github/MARKDOWN_NAMING_GUIDE.md](.github/MARKDOWN_NAMING_GUIDE.md) for complete guide

### Directory Access Patterns:

- **Daily development**: Root, scripts/, docs/guides/
- **Building/deploying**: Root (build scripts)
- **Testing**: tests/, scripts/testing/
- **Documentation**: docs/ (all subdirectories)
- **Analysis**: game.json, dll_exports/, docs/analysis/

---

## 🚀 Quick Navigation

| Task | Location |
|------|----------|
| Start MCP server | `bridge_mcp_ghidra.py` |
| Deploy plugin | `deploy-to-ghidra.ps1` |
| Run tests | `pytest tests/` |
| Extract functions | `scripts/functions-extract.ps1` |
| Process data | `scripts/data-process.ps1` |
| Fix ordinals | `ordinal_linkage_manager.py` (root) |
| View API docs | `docs/API_REFERENCE.md` |
| Read guides | `docs/guides/` |
| Check analysis | `docs/analysis/GAME_EXE_BINARY_ANALYSIS.md` |
| Find examples | `examples/` |

---

## 📊 Statistics

- **Root-level files**: ~40 files (to be reduced to ~25)
- **Documentation files**: ~15 in root, ~30 in docs/
- **Python scripts**: ~172 total
- **PowerShell scripts**: ~24 total
- **Directories**: 15+ main directories

---

**Last Updated**: November 6, 2025
**Version**: 1.0.0
**Status**: Organization in progress
