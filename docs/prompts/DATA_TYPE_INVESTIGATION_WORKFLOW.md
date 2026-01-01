# Data Type Investigation and Structure Standardization Workflow

## Overview

This workflow provides a systematic approach to identify correct data types for function parameters, discover complete data structure definitions by analyzing usage patterns, and standardize parameter types across the codebase. The methodology ensures proper structure type identification, creation of missing structure definitions, cross-function validation, and comprehensive type application to improve decompilation quality.

The core principle is to **investigate how each parameter is used across ALL functions to determine its true data type**, rather than guessing based on single instances. This approach reveals complete structure definitions and ensures consistent typing throughout the codebase.

## Core Concepts

### Structure Type vs Parameter Name
A parameter named `pUnit` or `int *pUnit` tells you it's a pointer, but doesn't reveal the actual structure type. You must investigate:
- How is the parameter dereferenced?
- What offsets are accessed?
- What structure fields are accessed?
- What other functions use the same structure?

### Data Structure Discovery Pattern
Complete data structure discovery follows this pattern:
1. **Identify Target Pattern**: Search for parameters with generic types (int *, void *, uint *)
2. **Analyze Single Function**: Understand what the parameter is used for
3. **Cross-Reference Analysis**: Find all functions using the same structure type
4. **Structure Extraction**: Build complete structure definition from field offset analysis
5. **Type Application**: Apply structure type to ALL identified functions
6. **Verification**: Confirm structure field offsets match actual function usage patterns

### Identity-Based Naming
Structure names must describe what the object IS, not temporary states. Use:
- **GOOD**: UnitAny, Skill, SkillData, SkillTableEntry (identity)
- **BAD**: InitializedUnit, AllocatedSkill, ProcessedData (state-based)

## Methodology

### Phase 1: Target Pattern Identification

**Objective**: Find functions with parameters using generic pointer types that should be properly typed.

#### 1.1 Search for Parameter Patterns

Use search_functions_by_name or enhanced search to find functions with specific parameter patterns:

```
Search patterns to target:
- int *pUnit, int *pParameter (generic int pointers)
- uint *pValue, uint *pData (unsigned generic pointers)
- void *pBuffer, void *pData (void pointers)
- DWORD *pdwFlags, DWORD *pdwValue (typed but using Windows SDK)
```

**Tools**:
- `search_functions_by_name()` with pattern like "Process" or "Calculate"
- `analyze_function_complete()` to get current parameter types
- `get_function_variables()` to list actual parameter names and types

#### 1.2 Document Initial Findings

Create a tracking table:
```
| Function Name | Address | Parameter | Current Type | Usage Pattern | Inferred Type |
|---------------|---------|-----------|--------------|---------------|---------------|
| ProcessUnit | 0x401000 | pUnit | int * | Offset access at 0x4, 0xC, 0x20 | UnitAny * |
| ValidateUnit | 0x402000 | pUnit | int * | Offset access at 0x4, 0xC | UnitAny * |
```

### Phase 2: Single Function Analysis

**Objective**: Understand how a parameter is used to infer its structure type.

#### 2.1 Get Function Information

```
analyze_function_complete(function_name, include_xrefs=true, include_disasm=true)
```

Retrieve:
- Decompiled code showing parameter usage
- Disassembly showing offset accesses
- Cross-references to the function
- Variable information

#### 2.2 Analyze Parameter Usage

Examine both decompiled and assembly views for:

**Offset Access Patterns**:
```asm
MOV EAX, [pUnit + 0x4]    # Access offset 0x4
CMP DWORD [pUnit + 0xC], 0  # Compare at offset 0xC
MOV ECX, [pUnit + 0x20]   # Access offset 0x20
```

**Field Access Inference**:
- Offset 0x4: First meaningful field after header
- Offset 0xC: Third DWORD (12-byte offset)
- Offset 0x20: Possibly pointer or ID field

**Decompiled Code Hints**:
```c
if (pUnit == NULL) return;           // Null check required
int flags = *(int *)(pUnit + 0x4);   // Offset 0x4 is int field
int id = *(int *)(pUnit + 0x8);      // Offset 0x8 is int field
```

#### 2.3 Identify Structure Type Candidates

Based on usage patterns, identify potential structures:

**Questions to Answer**:
- Is the structure a game entity (Unit, Character, Item)?
- Is it skill-related (Skill, SkillData, SkillTableEntry)?
- Is it configuration data (Config, Settings)?
- What's the approximate size based on highest offset accessed?

**Verification Questions**:
- Are offsets aligned to 4-byte boundaries (DWORD), 2-byte (WORD), or 1-byte?
- Are there pointer fields (values that look like addresses)?
- Are there size/count fields (loop bounds)?
- Are there flag or status fields (bit operations)?

### Phase 3: Cross-Reference Analysis

**Objective**: Find ALL functions using the same parameter type and build complete structure definition.

#### 3.1 Search for Functions with Same Parameter

Use get_function_xrefs or search to find:
- Functions with same parameter name (pUnit, pValue)
- Functions with matching offset access patterns
- Functions in related domains (all skill-related, all unit-related)

**Pattern Matching**:
```
Search for:
- Functions accessing "pUnit" or similar parameter names
- Functions with offset accesses in the same range (0x0-0xFF)
- Functions called from same caller context
```

#### 3.2 Build Offset Map

Create comprehensive offset map from all functions:

```
| Offset | Size | Field Name | Access Type | Accessed By | Inferred Type |
|--------|------|-----------|-------------|-------------|---------------|
| 0x0 | 4 | dwType | READ | ProcessUnit, ValidateUnit | uint |
| 0x4 | 4 | dwFlags | READ,WRITE | ProcessUnit, ModifyUnit | uint |
| 0x8 | 4 | pNext | READ | EnumerateUnits | UnitAny * |
| 0xC | 2 | wHealth | READ,WRITE | ApplyDamage, HealUnit | ushort |
| ... | ... | ... | ... | ... | ... |
```

**Offset Collection Strategy**:
1. List all functions using the structure
2. For each function, document every offset access
3. Merge into master offset map, noting access types (READ/WRITE/CALL)
4. Identify data types from:
   - Increment patterns (++dw suggests uint)
   - Comparison values (< 256 suggests byte)
   - Shift operations (>> 5 suggests bit field or index)

#### 3.3 Identify Gaps and Alignment

```
Offset 0x00-0x03: dwType (uint) - 4 bytes
Offset 0x04-0x07: dwFlags (uint) - 4 bytes
Offset 0x08-0x0B: [UNKNOWN] - 4 bytes
Offset 0x0C-0x0D: wHealth (ushort) - 2 bytes
Offset 0x0E-0x0F: [PADDING/ALIGNMENT] - 2 bytes
```

Note: Alignment padding is normal at structure boundaries.

### Phase 4: Search for Existing Structures

**Objective**: Find existing structure definitions that match your offset analysis.

#### 4.1 Search Data Types

```
list_data_types(category="struct", offset=0, limit=500)
search_data_types(pattern="Unit", limit=50)
search_data_types(pattern="Skill", limit=50)
```

#### 4.2 Compare Layouts

For promising candidates, use `search_data_types()` or `list_data_types()` to find matching structures, then examine:
- Field names and offsets
- Field types and sizes
- Total structure size
- Alignment information

**Comparison Process**:
```
Your Offset Map             Existing Structure
Offset 0x0: dwType         Offset 0x0: dwType (uint)
Offset 0x4: dwFlags        Offset 0x4: dwFlags (uint)
Offset 0x8: pNext          Offset 0x8: pNext (UnitAny *)
Offset 0xC: wHealth        Offset 0xC: wHealth (ushort)
```

If most offsets match, the existing structure is correct.

#### 4.3 Validate Structure Size

**Methods**:
1. Find stride in array access patterns (if structure is in array)
2. Find allocation size in malloc/new calls
3. Compare known offsets + field sizes against total usage

**Example**:
```asm
LEA ECX, [pBase + EAX*0x23C]  # 0x23C = 572 bytes = structure stride
```

### Phase 5: Structure Definition Creation (If Needed)

**Objective**: Create new structure if no suitable existing definition found.

#### 5.1 Determine Complete Field List

Build comprehensive field list from offset analysis:

```
Fields to Create:
- dwType (offset 0x0, 4 bytes): uint
- dwFlags (offset 0x4, 4 bytes): uint
- pNext (offset 0x8, 4 bytes): UnitAny *
- wHealth (offset 0xC, 2 bytes): ushort
- bResistance (offset 0xE, 1 byte): byte
- [PADDING] (offset 0xF, 1 byte): byte
- ... (continue for all offsets)
```

#### 5.2 Create Structure with create_struct

```
fields = [
    {"name": "dwType", "type": "uint"},
    {"name": "dwFlags", "type": "uint"},
    {"name": "pNext", "type": "UnitAny *"},
    {"name": "wHealth", "type": "ushort"},
    {"name": "bResistance", "type": "byte"},
    {"name": "bPadding", "type": "byte"},
    # ... more fields
]

create_struct("UnitAny", fields)
```

#### 5.3 Verify Structure Size

Confirm total structure size matches expected allocation or stride:
- Expected from offset analysis: Highest offset + field size
- Expected from array stride: Stride value from assembly patterns
- Expected from allocation: malloc/calloc argument values

**If Size Mismatch**:
- Add padding fields between non-contiguous offsets
- Verify field types and sizes are correct
- Check for alignment requirements (4-byte or 8-byte)

#### 5.4 Document Helper Structures

For complex data types with multiple related structures, create helper structures:

**Example - Skill-Related Structures**:
- `SkillTableEntry` (575 bytes): Master skill definition table
- `SkillObject` (48 bytes): Runtime skill execution state
- `SkillData` (52 bytes): Skill execution parameters
- `SkillContext` (468 bytes): Full execution context

Each serves different purpose:
- SkillTableEntry: Read-only template, shared across all instances
- SkillObject: Per-instance runtime state
- SkillData: Execution parameters passed between functions
- SkillContext: Full context for validation and state management

### Phase 6: Type Application

**Objective**: Apply identified structure types to all functions using the same structure.

#### 6.1 Identify All Functions to Update

Create list of all functions using the structure type:

```
Functions using UnitAny * :
- ProcessUnit (0x401000)
- ValidateUnit (0x402000)
- ApplyDamage (0x403000)
- HealUnit (0x404000)
- EnumerateUnits (0x405000)
(... etc)
```

#### 6.2 Apply Type to Parameters

For each function:

```
set_parameter_type(
    function_address="0x401000",
    parameter_name="pUnit",
    new_type="UnitAny *"
)
```

**Important**: Set types for ALL identified parameters in each function.

#### 6.3 Verify Type Application

After each batch of changes, verify using:
```
get_function_variables(function_name)
```

Confirm the parameter now shows correct type.

#### 6.4 Force Decompilation Refresh

After applying structure types, refresh decompilation:
```
get_decompiled_code(function_address, refresh_cache=True)
```

This updates decompiled view to show proper structure field names instead of raw offsets.

### Phase 7: Verification

**Objective**: Confirm structure types match actual function usage patterns.

#### 7.1 Field Offset Verification

For each structure, verify field offsets match actual assembly access:

```
Structure Definition          Assembly Access
Offset 0x0: dwType (uint)     MOV EAX, [pUnit + 0x0] ✓
Offset 0x4: dwFlags (uint)    CMP [pUnit + 0x4], 0   ✓
Offset 0x8: pNext (UnitAny*)  LEA ECX, [pUnit + 0x8] ✓
```

**Verification Steps**:
1. Get function disassembly for each accessor function
2. Document each offset access instruction
3. Compare accessed offsets to structure fields
4. Flag mismatches for investigation

#### 7.2 Type Consistency Checks

Verify type consistency across all functions:

```
Function ProcessUnit:
  Parameter: pUnit UnitAny * ✓
  Field access: [pUnit + 0x0] = dwType (uint) ✓
  Field access: [pUnit + 0x4] = dwFlags (uint) ✓

Function ValidateUnit:
  Parameter: pUnit UnitAny * ✓
  Field access: [pUnit + 0x0] = dwType (uint) ✓
  Field access: [pUnit + 0xC] = wHealth (ushort) ✓
```

#### 7.3 Cross-Function Usage Patterns

Verify parameter usage is consistent across functions:

**Pattern Analysis**:
- All functions null-check parameter: ✓
- All functions read dwType field: ✓
- All functions modify health field consistently: ✓
- Some functions read optional fields: (document)

#### 7.4 Alignment Verification

Check structure alignment assumptions:

```
If structure has:
  DWORD (4 bytes)
  DWORD (4 bytes)
  WORD (2 bytes)
  WORD (2 bytes)

Expected alignment: 4-byte (DWORD-aligned)
Expected size: 12 bytes (3 DWORDs)
```

**Verify in actual usage**:
- Is structure allocated on 4-byte boundaries?
- Are array elements stride-aligned?
- Do all accesses respect alignment?

## Implementation Workflow

### Quick Reference: Full Process

```
1. IDENTIFY TARGET PATTERNS
   - search_functions_by_name() or analyze_function_complete() on multiple functions
   - Document parameter names and current types

2. ANALYZE SINGLE FUNCTION
   - analyze_function_complete() to get decompiled code and disassembly
   - Identify offset accesses and usage patterns
   - Build initial offset map

3. CROSS-REFERENCE ANALYSIS
   - search_functions_by_name() to find similar functions
   - Get disassembly and variable info for each
   - Merge offset maps from all functions

4. SEARCH FOR EXISTING STRUCTURES
   - list_data_types() and search_data_types() to find candidates
   - search_data_types() to find matching structures
   - Verify size matches expected stride or allocation

5. CREATE STRUCTURE IF NEEDED
   - Build complete field list from offset analysis
   - create_struct() with proper field types
   - Verify total size is correct

6. APPLY TYPES TO ALL FUNCTIONS
   - set_parameter_type() for each function and parameter
   - Verify with get_function_variables()
   - get_decompiled_code() with refresh_cache=True

7. VERIFY COMPLETENESS
   - Document field offset mapping (Offset, Size, Field, Type, Usage)
   - Verify all structure accesses match field offsets
   - Confirm type consistency across all functions
   - Check alignment and stride patterns
```

## Examples

### Example 1: Identifying UnitAny * Parameters

**Initial Finding**:
```
Function ProcessUnit (0x401000):
  Parameter 1: int * pUnit  # Generic type

Assembly:
  MOV EAX, [pUnit + 0x0]    # Read at offset 0x0
  CMP [pUnit + 0x4], 0      # Compare at offset 0x4
```

**Investigation**:
- Offset 0x0: Some kind of identifier/type field
- Offset 0x4: Flags or status field
- Function appears to work with game entities

**Cross-Reference Search**:
- Found 12 functions with similar patterns
- All access offsets in range 0x0-0xFF
- All follow null-check pattern
- All modify specific fields (health, mana, etc.)

**Structure Analysis**:
- Maximum offset accessed: 0xF8 (248 bytes)
- Field types: mostly DWORD/WORD
- Structure size estimate: 252 bytes
- Matches existing UnitAny structure (252 bytes)

**Result**:
```
UnitAny * pUnit
  - dwType at offset 0x0
  - dwFlags at offset 0x4
  - wHealth at offset 0xC
  - ... (248 more bytes of game entity data)
```

Applied to all 12 functions.

### Example 2: Creating SkillTableEntry Structure

**Problem**: Functions access skill table with unknown structure type.

**Analysis**:
```asm
LEA ECX, [pSkillTable + EAX*0x23C + 0x1A4]  # Stride 0x23C, offset 0x1A4
MOV EDX, [ECX]                               # Read at +0x1A4
CMP [ECX + 0x4], 0                           # Compare at +0x1A8
```

**Offset Collection** (from 8 functions):
- 0x1A4: dwShiftAmount
- 0x1A5: dwWeaponCoeff
- 0x1A8: dwBaseDamage
- 0x1B0: dwStatBonus
- 0x1D8: dwPropertyMod

**Structure Creation**:
```
create_struct("SkillTableEntry", [
    {"name": "dwType", "type": "uint"},
    {"name": "dwId", "type": "uint"},
    # ... 100 more bytes of fields
    {"name": "dwShiftAmount", "type": "byte", "offset": 0x1A4},
    {"name": "dwWeaponCoeff", "type": "byte", "offset": 0x1A5},
    {"name": "dwBaseDamage", "type": "uint", "offset": 0x1A8},
    # ... more fields
])
```

**Total Size**: 575 bytes (matches 0x23C stride when accounting for alignment)

### Example 3: Helper Structure Creation

**Context**: SkillObject needed for skill execution state tracking

**Problem**: Runtime skill execution state not properly typed

**Analysis**:
- Functions create skill state with ~48 bytes
- Contains owner unit pointer, target pointer, skill ID, level
- Accessed together in execution functions

**Structure Created**:
```
SkillObject (48 bytes):
  - dwType: uint (skill type identifier)
  - pOwnerUnit: UnitAny * (unit executing skill)
  - pTargetUnit: UnitAny * (target of skill)
  - dwSkillId: uint (skill index)
  - dwLevel: uint (skill level)
  - dwCharges: uint (remaining uses)
  - pSkillData: SkillData * (execution parameters)
```

**Usage**:
- Created locally in ExecuteSkill function
- Passed to ValidateSkill, ApplySkillEffect functions
- Deallocated after execution

## Common Pitfalls and Solutions

### Pitfall 1: Incomplete Structure Definitions

**Problem**: Structure defined with only observed fields, missing data before first access.

**Solution**: When highest offset accessed is 0x100 but field starts at 0x0, structure likely starts at 0x0 with all preceding bytes. Add padding fields for unknown regions or allocate space for them.

### Pitfall 2: Incorrect Field Types

**Problem**: Field type guessed incorrectly from usage pattern.

**Example**:
```asm
ADD EDX, [pData + 0x4]   # Looks like int
MOV [pData + 0x4], 100   # But 100 is uint range
```

**Solution**: Consider both read AND write patterns. An increment suggests signed, but range of values (0-65535) suggests unsigned. Cross-reference all functions accessing the field.

### Pitfall 3: Alignment Assumptions

**Problem**: Structure defined with wrong alignment, causing offset mismatches.

**Solution**: Verify:
- Largest field in structure determines alignment (QWORD = 8-byte alignment)
- Padding is inserted by compiler for alignment
- Array stride must account for padding

### Pitfall 4: Missing Helper Structures

**Problem**: Trying to fit unrelated data into single structure.

**Example**: SkillTableEntry (575 bytes) vs SkillObject (48 bytes) - both skill-related but different purposes.

**Solution**: Create separate structures for:
- Static data (SkillTableEntry): Read-only templates
- Dynamic data (SkillObject): Runtime state
- Parameter blocks (SkillData): Execution parameters

## Verification Checklist

Before marking investigation complete:

- [ ] All functions using the structure type identified and listed
- [ ] Offset map created with all fields from all functions
- [ ] Existing structures searched and compared
- [ ] Structure created or identified with correct name (identity-based)
- [ ] All identified functions updated with correct parameter types
- [ ] Type application verified with get_function_variables()
- [ ] Decompilation refreshed with refresh_cache=True
- [ ] Field offset verification completed for each accessor function
- [ ] Structure size matches expected stride or allocation size
- [ ] Alignment and padding documented
- [ ] Cross-function type consistency confirmed
- [ ] Helper structures created for complex related types

## Documentation Standards

When documenting structure investigation results:

1. **Structure Definition Table**:
   ```
   | Offset | Size | Field Name | Type | Description | Accessed By |
   |--------|------|-----------|------|-------------|-------------|
   | 0x0 | 4 | dwType | uint | Entity type identifier | 12 functions |
   | 0x4 | 4 | dwFlags | uint | State flags | 8 functions |
   ```

2. **Type Application Summary**:
   ```
   Total functions updated: 12
   Parameter: pUnit
   Old type: int *
   New type: UnitAny *
   Verification: All functions access fields at 0x0-0xF8
   ```

3. **Field Offset Verification**:
   ```
   ProcessUnit: [pUnit + 0x0] = dwType ✓
   ValidateUnit: [pUnit + 0x4] = dwFlags ✓
   ApplyDamage: [pUnit + 0xC] = wHealth ✓
   ```

## Related Workflows

- **FUNCTION_DOC_WORKFLOW_V2.md**: For complete function documentation using proper types
- **GLOBAL_DATA_ANALYSIS_WORKFLOW.md**: For global data structure identification
- **HUNGARIAN_NOTATION_REFERENCE.md**: For proper variable naming conventions
