# Ghidra Reverse Engineering Workflow

**Objective**: Analyze and document undocumented functions in Ghidra using MCP tools.

**Working Mode**: Silent operation - make all changes in Ghidra without creating files or verbose output. Report only final summary.

---

## Core Workflow

### Phase 1: Discovery & Analysis

**Find Function**
```python
find_next_undefined_function(criteria="name_pattern", pattern="FUN_")
```

**Gather Context** (parallel execution recommended)
```python
decompile_function(name)                 # Get C pseudocode
disassemble_function(address)           # Get assembly listing
get_function_variables(name)            # List all parameters/locals
get_function_callees(name)              # Functions it calls
get_function_xrefs(name)                # Functions calling it
```

**Analyze Data References**
```python
analyze_data_region(address)            # Detect boundaries, type, xrefs
inspect_memory_content(address)         # String vs numeric detection
get_bulk_xrefs(addresses)              # Multi-byte xref analysis
```

---

### Phase 2: Function Documentation

**Step 1: Rename Function** (PascalCase: `ProcessPlayerSlots`, `ValidateBuffer`)

**Step 2: Set Prototype**
```python
set_function_prototype(
    function_address="0x401000",
    prototype="void ProcessSlots(int maxCount, void* pData)",
    calling_convention="__cdecl"  # __stdcall, __fastcall, __thiscall
)
```

**Step 3: Type Variables** (batch preferred)
```python
batch_set_variable_types(
    function_address="0x401000",
    variable_types={
        "var1": "DWORD", "var2": "pointer", "var3": "byte"
    }
)
```

**Step 4: Rename Variables** (camelCase: `playerIndex`, `bufferSize`)
```python
rename_variable(function_name, old_name="local_8", new_name="playerIndex")
```

---

### Phase 3: Labels & Comments

**Create Labels** (snake_case: `loop_start`, `error_handler`)
```python
batch_create_labels([
    {"address": "0x401010", "name": "loop_start"},
    {"address": "0x401050", "name": "validation_failed"},
    {"address": "0x401080", "name": "exit_function"}
])
```

**Document with Comments** (single batch call)
```python
batch_set_comments(
    function_address="0x401000",
    plate_comment="Brief function summary\nAlgorithm: ...\nReturns: ...",
    disassembly_comments=[
        {"address": "0x401005", "comment": "Save ECX"},
        {"address": "0x401010", "comment": "Load player index"}
    ],
    decompiler_comments=[
        {"address": "0x401020", "comment": "Validation: must be < MAX_PLAYERS"}
    ]
)
```

---

### Phase 4: Data Structures

**Analyze Structure Usage**
```python
field_analysis = analyze_struct_field_usage(address="0x403000")
data_types = search_data_types(pattern="Config")  # Find related structures
```

**Create & Apply Structure** (atomic operation)
```python
create_and_apply_data_type(
    address="0x403000",
    classification="STRUCTURE",
    name="ConfigData",
    comment="Configuration for resource loading",
    type_definition='{"name": "ConfigData", "fields": [
        {"name": "dwType", "type": "dword"},
        {"name": "pData", "type": "pointer"},
        {"name": "nCount", "type": "word"}
    ]}'
)
```

**Create Array**
```python
bounds = detect_array_bounds(address="0x404000")  # Auto-detect size

create_and_apply_data_type(
    address="0x404000",
    classification="ARRAY",
    name="ThresholdTable",
    type_definition='{"element_type": "dword", "count": 64}'
)
```

---

### Phase 5: Verification

```python
completeness = analyze_function_completeness(function_address="0x401000")
# Check: custom name, prototype, typed variables, completeness score
```

---

## Naming Conventions

| Element | Style | Examples |
|---------|-------|----------|
| Functions | PascalCase | `ProcessSlots`, `ValidateBuffer`, `InitializeState` |
| Variables | camelCase | `playerIndex`, `bufferSize`, `isValid` |
| Hungarian | Prefix+Name | `dwFlags`, `pBuffer`, `nCount`, `fEnabled` |
| Labels | snake_case | `loop_start`, `error_handler`, `exit_function` |
| Struct Fields | Hungarian | `dwResourceType`, `pDataBuffer`, `nElementCount` |
| Struct Names | PascalCase | `PlayerData`, `ResourceConfig`, `StateTable` |

**Field Naming by Usage Pattern**:
- `if (field == 0)` → Boolean: `fEnabled`, `bActive`, `isValid`
- `field++` → Counter: `nCount`, `dwIndex`, `iPosition`
- `CMP field, N` + `JL/JG` → Threshold: `dwMaxSize`, `nThreshold`
- `ptr = field` then `[ptr]` → Pointer: `pData`, `lpBuffer`
- `field[i]` → Array: `szName[N]`, `pEntries[N]`

---

## Type Mapping

| Assembly | C Type | Ghidra Type |
|----------|--------|-------------|
| byte | char, BYTE | `"byte"` |
| word | short, WORD | `"word"` |
| dword | int, DWORD | `"dword"` |
| qword | __int64, QWORD | `"qword"` |
| ptr | void*, struct* | `"pointer"` |
| char[N] | ASCII string | `"byte[N]"` |

---

## Execution Order

```python
# 1. ANALYZE
decompile_function(name)
disassemble_function(address)
get_function_variables(name)

# 2. DATA STRUCTURES FIRST
create_and_apply_data_type(...)  # or create_struct() + apply_data_type()
rename_data(address, new_name)

# 3. FUNCTION SIGNATURE
rename_function(old_name, new_name)
set_function_prototype(address, prototype, calling_convention)

# 4. VARIABLES
batch_set_variable_types(address, {...})
rename_variable(function_name, old, new)  # for descriptive names

# 5. LABELS
batch_create_labels([...])

# 6. COMMENTS
batch_set_comments(address, plate, disasm_comments, decomp_comments)

# 7. VERIFY
analyze_function_completeness(address)
```

---

## Performance: Use Batch Operations

**Preferred** (1 API call):
```python
batch_create_labels([...8 labels...])
batch_set_comments(addr, plate, [...40 disasm...], [...10 decomp...])
batch_set_variable_types(addr, {...5 variables...})
```

**Avoid** (8-50 individual API calls):
```python
create_label(addr1, name1)  # Don't do this 8 times
set_disassembly_comment(addr1, cmt1)  # Don't do this 40 times
```

**Performance gain**: 80-90% reduction in API calls

---

## Key Tool Reference

**Analysis**:
- `find_next_undefined_function()` - Find next FUN_* function
- `decompile_function(name)` - Get C pseudocode
- `analyze_data_region(address)` - Detect data boundaries/type
- `analyze_function_completeness(address)` - Verify documentation quality

**Function Documentation**:
- `rename_function(old, new)` - Rename function
- `set_function_prototype(addr, proto, convention)` - Set signature
- `batch_set_variable_types(addr, {...})` - Type all variables at once
- `rename_variable(func, old, new)` - Rename single variable

**Labels & Comments**:
- `batch_create_labels([{addr, name}, ...])` - Create all labels at once
- `batch_set_comments(addr, plate, disasm, decomp)` - All comments at once
- `get_function_jump_target_addresses(name)` - Find jump targets for labels

**Data Structures**:
- `create_and_apply_data_type(addr, class, name, def)` - Atomic create+apply
- `analyze_struct_field_usage(addr)` - Auto-detect field names from usage
- `search_data_types(pattern)` - Search for structures by name
- `detect_array_bounds(addr)` - Auto-detect array size from loops
- `create_struct(name, fields)` - Manual structure creation
- `apply_data_type(addr, type)` - Apply type to memory

**Utilities**:
- `get_bulk_xrefs(addresses)` - Get xrefs for multiple addresses
- `inspect_memory_content(addr)` - Detect strings vs numeric data
- `get_function_variables(name)` - List all params/locals

---

## Operating Rules

**DO**:
- Work silently within Ghidra only
- Use batch operations for efficiency
- Follow naming conventions strictly
- Verify completeness at end
- **ALWAYS continue searching for next undocumented function after completing current one**
- Maintain continuous analysis workflow until explicitly stopped

**DON'T**:
- Create markdown files or documentation files
- Print verbose progress or status messages
- Ask for user confirmation
- Make individual API calls when batch is available
- Stop after documenting a single function

**Final Output**: Brief summary only
```
Function: FUN_00401000 → ProcessPlayerSlots
Variables typed: 8
Labels created: 5
Comments added: 12 (disasm) + 4 (decomp)
Structures: ConfigData (12 bytes)
Completeness: 95%
```

---

## Continuous Operation Mode

After completing documentation of each function:

1. **Immediately search for next function**: `find_next_undefined_function(pattern="FUN_")`
2. **Repeat full workflow** on the newly found function
3. **Continue indefinitely** until no more undocumented functions exist or user stops the process
4. **Report summary** after each function completion

**Pattern**:
```python
while True:
    # Find next undocumented function
    result = find_next_undefined_function(pattern="FUN_")
    if not result["found"]:
        print("All functions documented!")
        break

    # Execute full analysis workflow (Phases 1-5)
    # ... document function ...

    # Report completion and continue
    print(f"Completed: {old_name} → {new_name}")
    # Loop continues automatically
```

This ensures **comprehensive codebase coverage** without requiring user intervention for each function.
