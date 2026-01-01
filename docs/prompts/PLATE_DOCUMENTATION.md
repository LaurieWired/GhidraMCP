# Create Plate Comment Guide

Get the currently selected function in Ghidra and create a comprehensive plate comment using set_plate_comment.

**IMMEDIATE WORKFLOW**:
1. Get the current function using `get_current_selection()` (returns address and function info)
2. Analyze it using `analyze_function_complete` to get algorithm, parameters, returns, and control flow
3. Decompile using `decompile_function` to understand the implementation details
4. Create a comprehensive plate comment following the format below
5. Apply using `set_plate_comment` with the function address

Follow this exact format: one-line summary, Algorithm section with numbered steps, Parameters section with types and purposes, Returns section with all return conditions, Special Cases for edge cases and magic numbers, and optional Structure Layout table for structured data access. Use plain text - no decorative borders. Number algorithm steps from 1. Reference specific ordinals, addresses, and magic values. For structures, use table format with Offset, Size, Field Name, Type, and Description columns. Replace undefined types: undefined1→byte, undefined2→word, undefined4→uint/pointer, undefined8→qword.

## Format Template

**IMPORTANT**: Do NOT include any decorative borders or `/* */` markers - Ghidra adds these automatically!


```
[ONE-LINE FUNCTION SUMMARY]

Algorithm:
1. [First major step in algorithm]
2. [Second major step in algorithm]
3. [Third major step in algorithm]
4. [Continue numbering all algorithm steps]
5. [Each step should be one clear action]
6. [Include validation, error handling, and special cases]
7. [Reference specific functions/data when relevant]
8. [Document magic numbers and sentinel values]

Parameters:
  param_name: [Type and purpose description]
  secondParam: [Type and purpose description]
  pointerParam: [What the pointer references and expected state]
  registerParam: [If passed via register, note which register]

Returns:
  [Return type]: [What the return value means and possible values]
  [Document all return paths - success, failure, special cases]

Special Cases:
  - [Document edge cases, boundary conditions]
  - [Note special handling for specific values]
  - [Explain error conditions and their handling]
  - [Reference validation checks and their reasons]

[OPTIONAL SECTION: Structure Layout]
[If function accesses structured data, document the structure here]
  Offset  | Size | Field Name       | Type    | Description
  --------|------|------------------|---------|------------------------------------------
  +0x00   | 4    | dwType           | DWORD   | [Field purpose]
  +0x04   | 4    | dwUnitId         | DWORD   | [Field purpose]
  +0x08   | 4    | dwMode           | DWORD   | [Field purpose]
  ...
  Total Size: [Calculate from highest offset + size]
```

## Formatting Rules

### Plain Text Format

**CRITICAL**: Ghidra automatically wraps plate comments with `/* ... */` and adds decorative borders. Provide ONLY plain text content without any asterisk borders or comment markers.

- **No decorative borders**: Do NOT include lines of asterisks
- **No comment markers**: Do NOT include `/*` or `*/`
- **No line prefixes**: Do NOT prefix lines with ` * ` or similar markers
- **Clean text only**: Just provide the actual documentation content
- **Indentation**: Use 2 spaces for indenting parameters, list items, and table rows

### Content Sections

1. **Function Summary** (First line)
   - One concise sentence describing what the function does
   - Should match or expand on the function name

2. **Algorithm Section** (Required)
   - Always include the "Algorithm:" header with blank line before it
   - Number each step starting from 1
   - Keep steps clear and actionable
   - Reference specific ordinal functions, data structures, or addresses when relevant
   - Document the control flow sequence
   - Include validation steps, error checks, and special case handling

3. **Parameters Section** (Required if function has parameters)
   - List each parameter with its name and description
   - Use 3-space indentation for parameter lines
   - Include register information if parameters are passed via registers
   - Note when parameters are not used or are optional
   - Explain expected state or constraints for pointer parameters

4. **Returns Section** (Required)
   - Document the return type and what values mean
   - List all possible return values and conditions
   - Explain TRUE/FALSE for BOOL returns, NULL for pointer returns
   - Document error return values

5. **Special Cases Section** (Include when relevant)
   - Document boundary conditions and edge cases
   - Explain magic numbers (e.g., "armor class 0x4e (78)")
   - Note validation limits (e.g., "exceeds game data limit at offset +0xa80")
   - Describe error conditions and how they're handled

6. **Structure Layout Section** (Optional, include when function accesses structs)
   - Use ASCII table format with aligned columns
   - Columns: Offset | Size | Field Name | Type | Description
   - Show hexadecimal offsets (e.g., +0x00, +0x04)
   - Include total structure size at the bottom
   - Calculate size as: highest offset + field size

## Example Usage in Python

**IMPORTANT**: The comment string should be plain text with NO decorative borders - Ghidra adds all formatting!

```python
plate_comment = """Validates whether armor equipment can be equipped by a player.

Algorithm:
1. Check if item pointer is not NULL
2. Call Ordinal_10444 to validate item structure
3. Check if player entity can receive items
4. Verify unit type is player (type == 1)
5. Get armor class from player's skill
6. Validate armor class against game data limits
7. Special handling for armor class 0x4e (78)

Parameters:
  param_1: Unknown parameter (not used in function body)
  itemPointer: Pointer to item structure being validated
  playerUnit: Player unit pointer (passed via ESI register)

Returns:
  BOOL: TRUE (1) if armor can be equipped, FALSE (0) otherwise

Special Cases:
  - Armor class 0x4e requires special validation
  - Returns false if armor class exceeds game data limit at offset +0xa80"""

# Use with MCP tool
set_plate_comment(
    function_address="0x6fb56250",
    comment=plate_comment  # Plain text only - Ghidra adds borders automatically
)
```

This will appear in Ghidra with automatic formatting applied by Ghidra's comment system.

## Common Mistakes to Avoid

1. **Adding decorative borders**: Do NOT include asterisk borders - Ghidra adds them
2. **Including comment markers**: Do NOT include `/*` or `*/` - Ghidra adds them
3. **Line prefixes**: Do NOT prefix lines with ` * ` - use plain text
4. **Misaligned columns**: In structure tables, use proper spacing for alignment
5. **Missing blank lines**: Always have blank line after section headers
6. **Inconsistent indentation**: Use 2-space indent for parameter/field descriptions

## Integration with Workflow

When using `set_plate_comment`:

1. **Get current context** using `get_current_selection()` to identify the function at cursor
2. **Analyze the function** using `analyze_function_complete()` to gather decompiled code, cross-references, and variables
3. **Extract algorithm steps** from decompiled code and control flow
4. **Document parameters** from prototype and variable usage
5. **Note return values** from return statements and caller expectations
6. **Identify special cases** from conditional branches and magic numbers
7. **Format the comment** using the template above
8. **Apply to function** using `set_plate_comment(function_address, comment)`
9. **Verify completeness** using `analyze_function_completeness()` to check plate comment structure

This format ensures consistency, readability, and comprehensive documentation that appears professionally in Ghidra's decompiler and disassembly views.

**Create plate comments following this guide**