# GhidraMCP v1.7.0 Release Notes

## Major Features: Variable Storage Control & Decompilation Tools

This release adds powerful new capabilities for fixing decompilation issues caused by compiler optimizations, specifically targeting the EBP register reuse problem and similar patterns.

## New Endpoints (4 total)

### 1. `set_variable_storage` - Variable Storage Information

**Endpoint**: `POST /set_variable_storage`
**MCP Tool**: `set_variable_storage(function_address, variable_name, storage)`

Provides detailed information about variable storage and guidance on changing it.

**Parameters**:
- `function_address`: Function address in hex (e.g., "0x6fb6aef0")
- `variable_name`: Variable to inspect (e.g., "unaff_EBP")
- `storage`: Desired storage specification (e.g., "Stack[-0x4]:4")

**Returns**:
- Current variable storage location
- Requested storage specification
- Step-by-step GUI instructions for manual changes
- Alternative approaches using scripts

**Use Case**: Get information about problematic variables like `unaff_EBP` and learn how to fix them.

### 2. `force_decompile` - Fresh Decompilation

**Endpoint**: `POST /force_decompile`
**MCP Tool**: `force_decompile(function_address)`

Forces Ghidra to create a fresh decompilation, bypassing all caches.

**Parameters**:
- `function_address`: Function address in hex format

**Returns**:
- Complete fresh decompiled C code

**Use Case**: After making changes to function signatures, data types, or flow overrides, get updated decompilation.

**Example Workflow**:
```python
# 1. Clear flow override
clear_instruction_flow_override("0x6fb6af51")

# 2. Set function to returning
set_function_no_return("0x6fabc3fa", False)

# 3. Force fresh decompilation
result = force_decompile("0x6fb6aef0")
print(result)  # See the updated code
```

### 3. `run_script` - Script Execution Guidance

**Endpoint**: `POST /run_script`
**MCP Tool**: `run_script(script_path, args="")`

Provides guidance on running Ghidra scripts for automation.

**Parameters**:
- `script_path`: Path to Ghidra script (.java or .py)
- `args`: Optional arguments (placeholder for future enhancement)

**Returns**:
- Instructions for running scripts via GUI
- Headless analyzer command examples
- Alternative automation approaches

**Note**: Due to Ghidra API limitations, actual script execution requires GUI or headless mode. This tool provides the necessary guidance.

### 4. `list_scripts` - Script Discovery

**Endpoint**: `GET /list_scripts?filter=<pattern>`
**MCP Tool**: `list_scripts(filter="")`

Lists common Ghidra script locations and provides discovery guidance.

**Parameters**:
- `filter`: Optional filter pattern (for future enhancement)

**Returns**:
- Common script directory locations
- Instructions for browsing scripts via GUI
- Search tips

## Updated Features

### Enhanced Workflow Support

The v1.7.0 tools work together to solve complex decompilation issues:

**Complete EBP Register Reuse Fix Workflow**:

```python
# Step 1: Analyze the problem
vars = get_function_variables("ProcessDualManaCostSkillWithAlternateCallbackHandlerAndAdvancedValidation")
# Identify: unaff_EBP with storage "EBP:4"

# Step 2: Get storage information
info = set_variable_storage("0x6fb6aef0", "unaff_EBP", "Stack[-0x4]:4")
# Returns: Current storage, instructions for manual fix

# Step 3: Clear instruction-level flow overrides
clear_instruction_flow_override("0x6fb6af51")

# Step 4: Fix function-level flow analysis
set_function_no_return("0x6fabc3fa", False)  # Make GetItemDirectionFromEntity returning

# Step 5: Force fresh decompilation
decompiled = force_decompile("0x6fb6aef0")
# See the improved (though not perfect) decompilation
```

## Technical Details

### Why Not Full Programmatic Control?

Ghidra's variable storage API has intentional limitations:

1. **VariableStorage Class**: No public `parseStorage()` method in Ghidra 11.4.2
2. **Variable Interface**: Limited mutation methods for storage changes
3. **Decompiler Integration**: Storage changes require high-level Pcode analysis

**Our Approach**:
- Provide detailed information and guidance
- Enable informed manual fixes via GUI
- Support script-based automation for advanced users
- Focus on tools that DO have full API support (force_decompile)

### What Works Programmatically

✅ **Fully Implemented**:
- `force_decompile` - Complete fresh decompilation
- `clear_instruction_flow_override` - Remove CALL_TERMINATOR overrides
- `set_function_no_return` - Control function flow analysis
- Variable storage **inspection** (current location, type, etc.)

⚠️ **Guidance Only**:
- Variable storage **modification** (requires GUI or custom script)
- Script execution (requires GUI or headless mode)

## Migration Guide

### From v1.6.7 to v1.7.0

**New Tools Available**:
```python
# v1.6.7: Manual workflow
# 1. Clear override manually
# 2. Change function properties manually
# 3. Hope decompilation updates

# v1.7.0: Automated workflow
clear_instruction_flow_override("0x6fb6af51")
set_function_no_return("0x6fabc3fa", False)
result = force_decompile("0x6fb6aef0")  # ← NEW: Force fresh analysis
```

**Enhanced Debugging**:
```python
# Get detailed variable information
info = set_variable_storage("0x6fb6aef0", "unaff_EBP", "Stack[-0x4]:4")
# Shows: Current storage, instructions, alternatives
```

## Known Limitations

### Variable Storage Modification

**Issue**: Cannot programmatically change variable storage through REST API
**Reason**: Ghidra API design requires UI interaction or Pcode-level scripting
**Workaround**: Use `set_variable_storage()` to get instructions, then:
1. Follow GUI instructions provided by the tool
2. Write custom Ghidra script (see `FixEBPRegisterReuse.py`)
3. Use Ghidra's decompiler right-click menu

### Script Execution

**Issue**: Cannot execute Ghidra scripts via REST API
**Reason**: Scripts require GhidraScript runtime environment
**Workaround**: Use `run_script()` for guidance, then:
1. Run via Ghidra GUI Script Manager
2. Use headless analyzer: `analyzeHeadless ... -postScript script.py`
3. Implement functionality as new MCP endpoint

### Decompiler Fundamental Limitations

**Issue**: Some compiler optimizations confuse the decompiler regardless of fixes
**Example**: EBP register reuse after PUSH EBP
**Reality**: Even after all fixes, decompilation may be incomplete
**Solution**: Use disassembly view as authoritative source

## Example: Complete EBP Fix Attempt

```python
from bridge_mcp_ghidra import *

# The problematic function
func_addr = "0x6fb6aef0"
func_name = "ProcessDualManaCostSkillWithAlternateCallbackHandlerAndAdvancedValidation"

print("=== Step 1: Analyze Current State ===")
vars = get_function_variables(func_name)
print(vars)  # Shows unaff_EBP with EBP:4 storage

print("\n=== Step 2: Get Storage Fix Guidance ===")
info = set_variable_storage(func_addr, "unaff_EBP", "Stack[-0x4]:4")
print(info)  # Provides manual fix instructions

print("\n=== Step 3: Fix Flow Overrides ===")
# Clear instruction-level override
clear_instruction_flow_override("0x6fb6af51")

# Fix function-level attribute
set_function_no_return("0x6fabc3fa", False)

print("\n=== Step 4: Force Fresh Decompilation ===")
result = force_decompile(func_addr)
print(result)

print("\n=== Step 5: Compare with Disassembly ===")
disasm = disassemble_function(func_addr)
print(disasm)  # The authoritative source

print("\n=== Conclusion ===")
print("Decompilation improved but still incomplete due to EBP reuse.")
print("Disassembly shows complete logic with all 7 phases.")
print("Use disassembly for accurate analysis.")
```

## Files Modified

- `src/main/java/com/xebyte/GhidraMCPPlugin.java`: Added 4 new endpoints
- `bridge_mcp_ghidra.py`: Added 4 new MCP tools
- `pom.xml`: Version 1.7.0
- `src/main/resources/extension.properties`: Version 1.7.0

## Statistics

- **Total Endpoints**: 107 (97 implemented + 10 ROADMAP v2.0)
- **New in v1.7.0**: 4 endpoints
- **Lines of Code**: ~9,400 (Java plugin)
- **Build Size**: 112KB

## Next Steps

### For Users

1. **Try the new workflow** on your EBP register reuse issue
2. **Use `force_decompile()`** after making any changes
3. **Follow the guidance** from `set_variable_storage()` for manual fixes
4. **Accept the limitation**: Disassembly is authoritative for complex optimizations

### For Future Development (v1.8.0+)

**Potential Enhancements**:
1. Advanced Pcode-based variable storage modification
2. Custom decompiler callback for register reuse detection
3. Automated pattern recognition for common optimization issues
4. Integration with Binary Ninja or IDA for comparison

**Community Contributions Welcome**:
- Custom scripts for common patterns
- Documentation improvements
- Bug reports and feature requests

## Acknowledgments

This release directly addresses the EBP register reuse issue discovered during analysis of Diablo II game DLL functions. The tools provide maximum programmatic support within Ghidra's API constraints while offering clear guidance for manual steps.

---

**Full Changelog**: https://github.com/bethington/ghidra-mcp/releases/tag/v1.7.0
**Documentation**: See `docs/EBP_REGISTER_REUSE_SOLUTIONS.md`
**Scripts**: `FixEBPRegisterReuse.py`, `FixEBPRegisterReuse.java`
