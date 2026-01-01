# Release Notes v1.9.3

**Release Date**: November 14, 2025  
**Version**: 1.9.3  
**Type**: Documentation & Workflow Enhancement Release

## Overview

Version 1.9.3 focuses on comprehensive documentation organization, enhanced Hungarian notation support, and improved variable renaming workflows. This release significantly improves the developer experience with better structured documentation and more robust AI-assisted reverse engineering workflows.

## 📚 Documentation Organization

### Reorganized Project Structure
- **Moved scattered release files** to proper `docs/releases/` hierarchy
- **Created `docs/project-management/`** for administrative documentation
- **Added comprehensive navigation** with `docs/README.md` and `docs/releases/README.md`
- **Eliminated root clutter** by organizing all markdown files appropriately

### Enhanced Documentation Navigation
- **Clear directory structure** with logical categorization
- **Version-specific release docs** properly organized by version
- **Administrative docs** separated from technical guides
- **AI workflow docs** clearly categorized in prompts directory

## 🔧 Hungarian Notation Improvements

### Enhanced Pointer Type Support
- **Double pointer types**: Added `void **` → `pp`, `char **` → `pplpsz`, `byte **` → `ppb`
- **Const pointer types**: Added `const char *` → `lpcsz`, `const void *` → `pc`
- **Windows SDK integration**: Mappings for `LPVOID`, `LPCSTR`, `LPWSTR`, `PVOID`
- **Function pointer refinement**: Distinguish callbacks (`pfnCallback`) from direct calls

### Type System Enhancements
- **Fixed spacing standards**: Corrected `char **` notation (removed spaces)
- **Array vs pointer clarity**: Distinguished stack arrays from pointer parameters
- **Comprehensive coverage**: Complete pointer-to-pointer type mapping
- **Best practices compliance**: Industry-standard Hungarian notation patterns

## 🎯 Variable Renaming Workflow

### Comprehensive Variable Identification
- **Dual-view analysis**: Mandated examining both decompiled code and disassembly
- **Complete variable coverage**: Include all parameter types, SSA variables, register inputs
- **Assembly-only variables**: Identify register spills and stack offsets not in decompiler
- **No pre-filtering**: Attempt renaming ALL variables regardless of name patterns

### Enhanced Reliability
- **Reliable failure detection**: Use `variables_renamed` count as sole indicator
- **Eliminated assumptions**: Never assume non-renameability from name patterns
- **Improved documentation**: Better comment examples for non-renameable variables
- **Comprehensive coverage**: Handle all variable types systematically

## 🛠 Build & Development

### Script Fixes
- **Resolved class name mismatches**: Fixed `CompleteDocumentation.java` and `RenameToCRTStartup.java`
- **Updated deprecated APIs**: Replaced `getFunction(String)` with `getFunctionByName(String)`
- **Build compatibility**: Ensured all Ghidra scripts compile correctly

### Workflow Efficiency
- **Streamlined processes**: More efficient function documentation workflows
- **Enhanced type mapping**: Precise Hungarian notation type-to-prefix mapping
- **Reduced redundancy**: Eliminated verbose explanations while maintaining clarity

## Migration Notes

### For Developers
- **Update bookmarks**: Documentation has moved to organized `docs/` structure
- **Check navigation**: Use new `docs/README.md` for documentation overview
- **Follow new standards**: Apply enhanced Hungarian notation rules

### For AI Workflows
- **Use updated prompts**: Enhanced `FUNCTION_DOC_WORKFLOW_V2.md` with better pointer handling
- **Apply new variable workflow**: Use comprehensive variable identification approach
- **Follow organized structure**: Reference properly organized documentation

## File Changes

### New Files
- `docs/README.md` - Comprehensive documentation navigation
- `docs/releases/README.md` - Release documentation index
- `docs/project-management/` - Administrative documentation directory
- `docs/releases/v1.9.3/` - This release's documentation

### Updated Files
- `pom.xml` - Version bumped to 1.9.3
- `CHANGELOG.md` - Added v1.9.3 release notes
- `docs/prompts/FUNCTION_DOC_WORKFLOW_V2.md` - Enhanced Hungarian notation
- Various Ghidra scripts - Fixed compilation issues

### Moved Files
- Release docs moved from root to `docs/releases/v1.9.2/`
- Administrative docs moved to `docs/project-management/`

## Compatibility

- **Ghidra**: Compatible with Ghidra 11.4.2+
- **Java**: Requires Java 21+
- **Python**: Compatible with Python 3.8+
- **Existing workflows**: Fully backward compatible

## Download & Installation

```bash
# Clone repository
git clone https://github.com/bethington/ghidra-mcp.git
cd ghidra-mcp

# Build
mvn clean package

# Deploy to Ghidra
.\deploy-to-ghidra.ps1
```

## Next Steps

1. Review new documentation organization in `docs/`
2. Update any documentation bookmarks or references
3. Apply enhanced Hungarian notation standards to new code
4. Use improved variable renaming workflows for better coverage

---

**Full Changelog**: [v1.9.2...v1.9.3](https://github.com/bethington/ghidra-mcp/compare/v1.9.2...v1.9.3)