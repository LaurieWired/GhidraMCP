# Ghidra MCP Tool Usage Guide

## Summary of Fixed Issues

The enhanced analysis prompt has been updated to use the **correct and reliable tool patterns** that work without retry loops.

### Issue Fixed: Type Application Pattern

**Previous approach (causes retries):**
```python
# ❌ PROBLEMATIC - create_and_apply_data_type has parameter format issues
create_and_apply_data_type(address, "PRIMITIVE", '{"type": "dword"}', "dwName", "comment")
# Error: type_definition must be JSON object/dict, got: String
```

**New approach (works first time):**
```python
# ✅ RELIABLE - Use separate, proven tools
apply_data_type(address, "dword")           # Step 1: Apply type
rename_or_label(address, "dwName")          # Step 2: Rename with Hungarian notation
set_decompiler_comment(address, "comment")  # Step 3: Add documentation
```

## Complete Workflow Pattern

### Type Application (Step 3)

```python
# Always use this three-step pattern:

# 1. Apply the data type
apply_data_type(address, type_name)

# 2. Rename with Hungarian notation
rename_or_label(address, hungarian_name)

# 3. Set documentation (in Step 6)
set_decompiler_comment(address, documentation)
```

### Supported Type Names for apply_data_type()

**Primitive Types:**
- `"dword"` - 32-bit unsigned integer
- `"word"` - 16-bit unsigned integer
- `"byte"` - 8-bit unsigned integer
- `"int"` - 32-bit signed integer
- `"short"` - 16-bit signed integer
- `"char"` - 8-bit signed character
- `"float"` - 32-bit IEEE 754 floating point
- `"double"` - 64-bit IEEE 754 floating point
- `"pointer"` - Generic pointer (32/64-bit depending on architecture)
- `"qword"` - 64-bit unsigned integer
- `"longlong"` - 64-bit signed integer
- `"bool"` - Boolean type

**String/Array Types:**
- `"char[N]"` - ASCII/ANSI string (e.g., `"char[6]"`, `"char[256]"`)
- `"word[N]"` - Array of 16-bit words
- `"dword[N]"` - Array of 32-bit dwords
- `"byte[N]"` - Array of bytes
- `"pointer[N]"` - Array of pointers

## Hungarian Notation Reference

Always use type prefixes in step 2 (rename_or_label):

| Type | Prefix | Examples |
|------|--------|----------|
| DWORD (unsigned 32-bit) | `dw` | `dwFlags`, `dwCount`, `dwUnitId` |
| WORD (unsigned 16-bit) | `w` | `wX`, `wY`, `wPort` |
| BYTE (unsigned 8-bit) | `b`, `by` | `bValue`, `byOpcode` |
| int (signed 32-bit) | `n` | `nCount`, `nIndex`, `nOffset` |
| short (signed 16-bit) | `n` | `nValue`, `nDelta` |
| char (signed 8-bit) | `c` | `cChar`, `cValue` |
| String (char[]) | `sz` | `szName`, `szPath`, `szGameName` |
| String (wchar_t[]) | `wsz`, `w` | `wszTitle`, `wName` |
| Pointer | `p` | `pData`, `pNext`, `pPlayerData` |
| Pointer (legacy) | `lp` | `lpBuffer`, `lpStartAddress` |
| Boolean (function-level) | `f` | `fEnabled`, `fIsActive` |
| Boolean (struct field) | `b` | `bActive`, `bVisible` |
| Function pointer | `fn` | `fnCallback`, `fnHandler` |
| Handle | `h` | `hFile`, `hThread`, `hModule` |
| Byte count | `cb` | `cbSize`, `cbBuffer` |

## Documentation Pattern

```python
# After apply_data_type() and rename_or_label() succeed:

documentation = """================================================================================
                    [TYPE] [Hungarian Name] @ [Address]
================================================================================
TYPE: [DataType] ([Size bytes]) - [Brief description]

VALUE: [Hex representation] ([Decimal if relevant])

PURPOSE:
[What this data represents and how it's used in 1-2 sentences]

[Additional relevant sections]
"""

set_decompiler_comment(address, documentation)
```

### Documentation Template Sections

**Mandatory:**
- `TYPE:` - Data type, size in bytes, brief description
- `VALUE:` - Hex and decimal values
- `PURPOSE:` - What the data represents and its primary usage

**Optional (add as relevant):**
- `SOURCE REFERENCE:` - Where data comes from (file, structure, etc.)
- `XREF COUNT:` - Number of cross-references
- `USAGE PATTERN:` - How/where the data is accessed
- `RELATED GLOBALS:` - Connected data items
- `INITIALIZATION:` - What function sets this
- `STRUCTURE LAYOUT:` - For pointer data
- `CONSTRAINTS:` - Value ranges, validation rules
- `EXAMPLES:` - Usage examples from decompiled code

## Complete Example

```python
# Address: 0x0040BC08, Data: "VIDEO" string (6 bytes)

# Step 3a: Apply type
apply_data_type("0x0040bc08", "char[6]")
# Returns: "Successfully applied data type 'char[6]' at 0x0040bc08 (size: 6 bytes)"

# Step 3b: Rename with Hungarian notation
rename_or_label("0x0040bc08", "szVideoSection")
# Returns: "Success: Renamed defined data at 0x0040bc08 to 'szVideoSection'"

# Step 6: Set documentation
set_decompiler_comment("0x0040bc08", """================================================================================
                    STRING szVideoSection @ 0x0040BC08
================================================================================
TYPE: char[6] (6 bytes) - Null-terminated ASCII string

VALUE: "VIDEO" (0x56 0x49 0x44 0x45 0x4F 0x00)

PURPOSE:
INI section name used to read video configuration settings from D2Server.ini file.
Passed to GetPrivateProfileIntA/GetPrivateProfileStringA for retrieving video-related
configuration keys from the VIDEO section.

XREF COUNT: 2 references
- LoadVideoConfigurationFromIni (2 calls for boolean and integer INI values)
""")
# Returns: "Success: Set comment at 0x0040bc08"
```

## When to Use Which Tool

### For Primitives (1-8 bytes)
1. `apply_data_type()` with primitive type name
2. `rename_or_label()` with `dw`, `w`, `n`, or `b` prefix
3. `set_decompiler_comment()` with documentation

### For Strings
1. `apply_data_type()` with `"char[N]"` or `"wchar_t[N]"`
2. `rename_or_label()` with `sz` or `wsz` prefix
3. `set_decompiler_comment()` with documentation

### For Pointers
1. `apply_data_type()` with `"pointer"`
2. `rename_or_label()` with `p` or `lp` prefix
3. `set_decompiler_comment()` with documentation

### For Arrays
1. `apply_data_type()` with `"type[count]"` (e.g., `"dword[64]"`)
2. `rename_or_label()` with type prefix (e.g., `adwValues`)
3. `set_decompiler_comment()` with documentation

### For Structures
1. `create_struct()` to define the structure with fields
2. `apply_data_type()` with structure name
3. `rename_or_label()` with descriptive instance name
4. `modify_struct_field()` if fields need renaming/type changes
5. `set_decompiler_comment()` with documentation

## Error Prevention Checklist

- ✓ Use `apply_data_type()` with string type names (not dicts)
- ✓ Use `rename_or_label()` for naming (it auto-detects data vs code)
- ✓ Always include Hungarian notation prefix in names
- ✓ Use `char[N]` format for strings (not just `char`)
- ✓ Use hex sizes for padding: `_1[0x158]` not `_1[344]`
- ✓ Call `set_decompiler_comment()` AFTER type and name are set
- ✓ Include header banner and all mandatory sections in documentation

## Related Tools

**For structure creation:**
- `create_struct(name, fields)` - Create a new structure type
- `modify_struct_field(struct_name, field_name, new_type, new_name)` - Update fields
- `search_data_types(pattern)` - Search for structures by name pattern

**For analysis:**
- `analyze_data_region(address)` - Get data type and boundaries
- `inspect_memory_content(address, length)` - Read raw memory
- `get_bulk_xrefs(addresses)` - Get cross-references

**For validation:**
- `validate_data_type_exists(type_name)` - Check if type exists
- `can_rename_at_address(address)` - Check what operation is appropriate

## Cross-Binary Documentation Propagation (v1.9.4+)

These tools enable documentation sharing across different versions of the same binary by matching functions based on their normalized opcode hashes.

### Function Hashing

```python
# Get hash for a single function
hash_info = get_function_hash("0x6FAB1234")
# Returns: {"hash": "abc123...", "instruction_count": 63, "has_custom_name": true}

# Get hashes for many functions (paginated)
result = get_bulk_function_hashes(offset=0, limit=500, filter="documented")
# filter options: "documented", "undocumented", "all"
```

### Documentation Export/Import

```python
# Export complete documentation from a well-documented function
docs = get_function_documentation("0x6FAB1234")
# Returns: name, prototype, plate_comment, parameters, locals, comments, labels

# Apply documentation to another function with matching hash
apply_function_documentation(
    target_address="0x6FAC0000",
    function_name="ProcessPlayerData",
    return_type="int",
    calling_convention="__fastcall",
    plate_comment="Processes player data structures.",
    parameters=[{"ordinal": 0, "name": "pPlayer", "type": "Player *"}]
)
```

### Index Management (High-Level Workflow)

```python
# Build index from documented functions across programs
build_function_hash_index(
    programs=["D2Client.dll 1.07", "D2Client.dll 1.08"],
    filter="documented",
    index_file="function_hash_index.json"
)

# Find functions matching a hash
matches = lookup_function_by_hash(hash="abc123...")
# Returns all programs/addresses with matching functions

# Propagate documentation to all matching functions
propagate_documentation(
    source_address="0x6FAB1234",
    target_programs=["D2Client.dll 1.08", "D2Client.dll 1.09"],
    dry_run=True  # Preview changes without applying
)
```

### Hash Normalization Details

The hash algorithm normalizes position-dependent values so identical functions at different addresses produce the same hash:

| Pattern | Normalization | Reason |
|---------|---------------|--------|
| Internal jumps | `REL+offset` | Relative to function start |
| External calls | `CALL_EXT` | Different addresses per binary |
| External data | `DATA_EXT` | Different addresses per binary |
| Small immediates (<0x10000) | `IMM:value` | Preserved (constants) |
| Large immediates | `IMM_LARGE` | May be addresses |
| Registers | Preserved | Part of algorithm logic |
