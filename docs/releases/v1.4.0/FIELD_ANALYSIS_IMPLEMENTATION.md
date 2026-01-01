# Field-Level Analysis Implementation (v1.4.0)

## Overview

Implemented three new MCP tools to enable automated field-level analysis of structures based on actual usage patterns in decompiled code. This addresses the limitation identified in the prompt optimization analysis where structures were being created with generic field names like `dwValue1`, `field2` instead of descriptive names based on actual usage.

## New MCP Tools

### 1. analyze_struct_field_usage

**Purpose**: Comprehensive field-level usage analysis for structures

**Endpoint**: `/analyze_struct_field_usage`

**Parameters**:
- `address`: Structure instance address (hex format)
- `struct_name`: Optional structure type name (auto-detected if omitted)
- `max_functions`: Maximum functions to analyze (default: 10)

**Returns**: JSON with per-field analysis:
```json
{
  "struct_address": "0x6fb835b8",
  "struct_name": "ConfigData",
  "struct_size": 28,
  "functions_analyzed": 5,
  "field_usage": {
    "0": {
      "field_name": "dwResourceType",
      "field_type": "dword",
      "offset": 0,
      "size": 4,
      "access_count": 12,
      "suggested_names": ["resourceType", "dwType", "nResourceId"],
      "usage_patterns": ["conditional_check", "assignment"]
    }
  }
}
```

**Implementation Details**:
- Finds all xrefs to structure address
- Decompiles each referencing function
- Analyzes decompiled code for field access patterns
- Detects usage patterns:
  - `conditional_check`: Field used in if/while conditions
  - `increment_decrement`: Field modified with ++/--
  - `assignment`: Field assigned to variables
  - `array_access`: Field accessed with array indexing
  - `pointer_dereference`: Field dereferenced with -> or .
- Extracts variable names from surrounding code
- Provides field-by-field access counts and suggestions

### 2. get_field_access_context

**Purpose**: Get specific usage examples for individual structure fields

**Endpoint**: `/get_field_access_context`

**Parameters**:
- `struct_address`: Structure instance address (hex format)
- `field_offset`: Offset of field within structure (e.g., 4 for second DWORD)
- `num_examples`: Number of usage examples to return (default: 5)

**Returns**: JSON with field access examples:
```json
{
  "struct_address": "0x6fb835b8",
  "field_offset": 4,
  "field_address": "0x6fb835bc",
  "examples": [
    {
      "access_address": "0x6fb6cae9",
      "ref_type": "DATA_READ",
      "assembly": "MOV EDX, [0x6fb835bc]",
      "function_name": "ProcessResource",
      "function_address": "0x6fb6ca00"
    }
  ]
}
```

**Implementation Details**:
- Calculates field address (struct_address + field_offset)
- Gets xrefs to specific field address
- Retrieves assembly instruction at each xref
- Identifies containing function for each access
- Provides access type (READ, WRITE, DATA)

### 3. suggest_field_names

**Purpose**: AI-assisted field name suggestions based on data types

**Endpoint**: `/suggest_field_names`

**Parameters**:
- `struct_address`: Structure instance address (hex format)
- `struct_size`: Optional structure size (auto-detected if 0)

**Returns**: JSON with naming suggestions per field:
```json
{
  "struct_address": "0x6fb835b8",
  "struct_name": "ConfigData",
  "struct_size": 28,
  "suggestions": [
    {
      "offset": 0,
      "current_name": "field0",
      "field_type": "dword",
      "suggested_names": ["dwValue", "nCount", "dwFlags"],
      "confidence": "medium"
    },
    {
      "offset": 4,
      "current_name": "field1",
      "field_type": "pointer",
      "suggested_names": ["pData", "lpBuffer", "pNext"],
      "confidence": "high"
    }
  ]
}
```

**Implementation Details**:
- Retrieves structure definition at address
- Generates Hungarian notation suggestions based on field types:
  - Pointers: `p*`, `lp*`
  - DWORDs: `dw*`
  - WORDs: `w*`
  - Bytes/chars: `b*`, `sz*`
  - Integers: `n*`, `i*`
- Provides generic fallback suggestions
- Assigns confidence levels based on type clarity

## Code Changes

### Java Plugin (GhidraMCPPlugin.java)

**Added Endpoints** (lines 828-860):
- `/analyze_struct_field_usage` - Comprehensive field analysis
- `/get_field_access_context` - Field-specific context
- `/suggest_field_names` - Type-based name suggestions

**Added Implementation Methods** (lines 5879-6252):
- `analyzeStructFieldUsage()` - Main analysis logic
- `FieldUsageInfo` - Helper class for tracking field usage
- `analyzeFieldUsageInCode()` - Pattern matching in decompiled code
- `getFieldAccessContext()` - Extract field access examples
- `suggestFieldNames()` - Generate name suggestions
- `generateFieldNameSuggestions()` - Hungarian notation logic
- `capitalizeFirst()` - String utility

**Version Update**:
- Updated from v1.3.0 to v1.4.0
- Updated endpoint count from 63+ to 66+
- Added field analysis features to description

### Python Bridge (bridge_mcp_ghidra.py)

**Added MCP Tools** (lines 2492-2679):
- `analyze_struct_field_usage()` - MCP wrapper for field analysis
- `get_field_access_context()` - MCP wrapper for field context
- `suggest_field_names()` - MCP wrapper for name suggestions

**Features**:
- Input validation using `validate_hex_address()`
- JSON formatting for readability
- Comprehensive docstrings with examples
- Error handling with `GhidraValidationError`

### Enhanced Prompt (ENHANCED_ANALYSIS_PROMPT.md)

**Updated Step 4**: Added automated field analysis workflow
- Section 4.1: Automated field analysis tools (RECOMMENDED)
- Section 4.2: Manual field analysis (ALTERNATIVE)
- Section 4.5: Refined to show both automated and manual approaches

**Updated Quick Reference**: Added v1.4.0 tools section highlighting new capabilities

## Usage Example

### Before (Manual Process - 20+ steps):
```python
# 1. Get xrefs to structure
xrefs = get_xrefs_to("0x6fb835b8", limit=10)

# 2. Manually decompile each function
for xref in xrefs:
    code = decompile_function(xref.function_name)
    # Manually read and analyze code

# 3. Manually identify patterns
# 4. Manually extract variable names
# 5. Manually map to field offsets
# 6. Delete old structure
# 7. Create new structure with better names
```

### After (Automated - 3 steps):
```python
# 1. Analyze all fields automatically
result = analyze_struct_field_usage("0x6fb835b8", max_functions=10)

# 2. Review suggestions and usage patterns
# result contains: access_count, suggested_names, usage_patterns per field

# 3. Create refined structure with suggested names
create_struct("RefinedStructName", [
    {"name": result.field_usage[0].suggested_names[0], "type": "dword"},
    {"name": result.field_usage[4].suggested_names[0], "type": "pointer"},
    ...
])
```

## Benefits

1. **Automation**: Reduces 20-30 manual tool calls to 1-3 automated calls
2. **Accuracy**: Field names based on actual usage patterns, not guesswork
3. **Speed**: Batch processing of multiple functions simultaneously
4. **Consistency**: Standardized Hungarian notation and naming conventions
5. **Context**: Provides evidence (access patterns, variable names) for naming decisions

## Testing Requirements

### Unit Tests Required:
- Test `analyze_struct_field_usage` with valid structure
- Test `get_field_access_context` with valid field offset
- Test `suggest_field_names` with various field types
- Test error handling for invalid addresses
- Test input validation for parameters

### Integration Tests Required:
- Test with actual Ghidra program loaded
- Test with various structure types (nested, arrays, pointers)
- Test with structures having no xrefs
- Test with structures having many xrefs (>100)
- Test field pattern detection accuracy

### Manual Testing Checklist:
- [ ] Create structure with generic field names
- [ ] Run analyze_struct_field_usage
- [ ] Verify suggested names match decompiled variable names
- [ ] Verify usage patterns match actual code
- [ ] Run get_field_access_context on specific field
- [ ] Verify assembly instructions are correct
- [ ] Run suggest_field_names
- [ ] Verify Hungarian notation suggestions
- [ ] Create refined structure with suggested names
- [ ] Verify improved readability in decompiler

## Documentation Updates

- [x] ENHANCED_ANALYSIS_PROMPT.md - Added v1.4.0 tools and examples
- [x] GhidraMCPPlugin.java - Updated version to 1.4.0
- [x] bridge_mcp_ghidra.py - Added comprehensive tool docstrings
- [ ] README.md - Should be updated with v1.4.0 features
- [ ] docs/API_REFERENCE.md - Should be updated with new endpoints

## Future Enhancements

1. **Pattern Recognition Improvements**:
   - Detect more complex patterns (state machines, bit flags, etc.)
   - Recognize common Windows API patterns (HANDLE, HWND, etc.)
   - Identify callback function pointers

2. **Machine Learning Integration**:
   - Train model on existing well-named structures
   - Predict field names with higher confidence
   - Learn from user corrections

3. **Cross-Function Analysis**:
   - Track field usage across entire call graph
   - Identify field invariants and constraints
   - Detect field relationships (e.g., size field for buffer)

4. **Interactive Refinement**:
   - Allow iterative refinement of field names
   - Provide feedback on name quality
   - Suggest improvements based on usage

5. **Export/Import Templates**:
   - Save field analysis results for reuse
   - Import common structure templates
   - Share naming conventions across projects
