# DATA DOCUMENTATION TEMPLATE

> **Instructions:** Replace all `[PLACEHOLDER]` sections with actual values from your analysis. Include all relevant details discovered through cross-reference analysis, decompilation, and assembly inspection.

---

## HEADER: Variable Declaration
**Format:** `[TYPE] [VariableName] @ [ADDRESS]`

**Description:** Start with the complete variable declaration showing data type, descriptive name (using Hungarian notation if appropriate), and memory address. This provides immediate context for what this documentation describes.

**Example:**
```
DWORD dwItemTypeCount @ 0x6fdf0aa0
```

---

## SECTION 1: TYPE INFORMATION

**Purpose:** Define the exact data type, size, and interpretation of the value.

**Contents:**
- **TYPE:** Raw data type with size (e.g., "DWORD (4 bytes) - unsigned 32-bit integer")
- **VALUE:** Current/typical value in both hex and decimal (e.g., "0x00000007 (7 decimal)")
- **HUNGARIAN NOTATION:** If applicable, explain the naming prefix convention (e.g., "'dw' prefix = DWORD")

**Format:**
```
TYPE: [DataType] ([ByteSize]) - [Description]
VALUE: [HexValue] ([DecimalValue])
HUNGARIAN NOTATION: '[prefix]' = [Meaning]
```

---

## SECTION 2: PURPOSE

**Purpose:** High-level explanation of what this variable represents and why it exists.

**Contents:**
- 1-3 sentence summary of the variable's role
- What system/subsystem it belongs to
- Primary function (e.g., "bounds checking", "configuration", "state tracking")
- Relationship to broader game mechanics

**Format:**
```
PURPOSE:
[2-3 sentence description explaining the variable's role in the system.
Include what it controls, tracks, or represents. Mention primary usage
patterns like bounds checking, array sizing, or configuration values.]
```

---

## SECTION 3: LOCATION IN GLOBAL STRUCTURE

**Purpose:** Describe where this variable exists within larger data structures or memory layout.

**Contents:**
- Parent structure name and address
- Field offset within parent structure
- Structure layout showing nearby related fields
- Address calculation formula showing how this address was derived
- Pointer chain if accessed indirectly (e.g., `global_ptr → struct_base → +offset → THIS_FIELD`)

**Format:**
```
LOCATION IN GLOBAL STRUCTURE:
This is field at offset +[OFFSET] in the [StructureName] structure pointed to by [GlobalPointer].

Structure layout:
  [GlobalPointer] @ [Address] → [BaseAddress] (base pointer)
    +[Offset1]: [FieldName1] ([description])
    +[Offset2]: [FieldName2] (THIS FIELD - [description])
    +[Offset3]: [FieldName3] ([description])

Calculated address: [BaseAddress] + [Offset] = [FinalAddress]
```

---

## SECTION 4: TYPICAL VALUE(S)

**Purpose:** Document expected values and their meanings.

**Contents:**
- Common/default value with explanation
- Enumeration of possible values if applicable
- Value ranges and what they represent
- Examples showing value interpretation in context

**Format:**
```
TYPICAL VALUE:
Value [HexValue] ([DecimalValue]) represents [Description]:
  [Index/Value 0]: [Meaning]
  [Index/Value 1]: [Meaning]
  [Index/Value 2]: [Meaning]
  ...
  ([Additional context about value ranges])
```

---

## SECTION 5: RELATED STRUCTURE DEFINITION

**Purpose:** Document the structure of data that this variable references or counts.

**Contents:**
- Structure size in bytes (decimal and hex)
- Key field offsets and their types
- Field descriptions showing what each offset contains
- Reference to where these structures come from (files, tables, etc.)

**Format:**
```
[STRUCTURE_NAME] STRUCTURE ([Size] bytes = [HexSize] per entry):
Each [StructureName] entry loaded from [Source] contains:
  +[Offset]: [Type] [FieldName] ([usage context])
  +[Offset]: [Type] [FieldName] ([usage context])
  +[Offset]: [Type] [FieldName] ([usage context])
  ... (additional fields for [categories of functionality])
```

---

## SECTION 6: USAGE PATTERNS

**Purpose:** Show how code actually uses this variable with concrete examples.

**Contents:**
- Primary usage categories (numbered list)
- Real code snippets from decompilation
- Function names and addresses where patterns occur
- Pseudocode showing typical access patterns
- Comments explaining what the pattern accomplishes

**Format:**
```
USAGE PATTERN ([XrefCount] cross-references):

1. [USAGE_CATEGORY_1] (primary usage):
   Pattern in [FunctionName] @ [Address]:
     [Pseudocode showing how variable is used]
     [Comments explaining the logic]

2. [USAGE_CATEGORY_2]:
   Pattern in [FunctionName] @ [Address]:
     [Pseudocode showing how variable is used]
     [Comments explaining the logic]

3. [USAGE_CATEGORY_3]:
   Pattern in [FunctionName] @ [Address]:
     [Pseudocode showing how variable is used]
     [Comments explaining the logic]
```

---

## SECTION 7: RELATED GLOBALS

**Purpose:** List other global variables that are closely related or accessed together.

**Contents:**
- Address and name of related globals
- Offset within parent structure if applicable
- Brief description of relationship
- Pointer chain showing how they connect

**Format:**
```
RELATED GLOBALS:
- [Address] = [VariableName] ([relationship description])
- [Address] = [VariableName] (THIS VARIABLE at +[Offset])
- [Address] = [GlobalPointer] ([description of pointer hierarchy])
```

---

## SECTION 8: ACCESS FORMULA/ALGORITHM

**Purpose:** Provide the exact formula for accessing related data using this variable.

**Contents:**
- Pseudocode showing access pattern
- Bounds checking logic
- Address calculation formula
- Concrete examples with actual values
- Step-by-step calculation showing intermediate values

**Format:**
```
ARRAY ACCESS FORMULA:
To access [DataType] at index i:
  if (i >= [MinBound] && i < [MaxBound]) {
    [AccessFormula]
  }

Example - [description of example]:
  if ([condition]) {
    address = [calculation];
    [resultVariable] = *([Type]*)address;
  }
```

---

## SECTION 9: INITIALIZATION

**Purpose:** Explain when and how this variable gets its value.

**Contents:**
- Initialization function name and address
- When initialization occurs (startup, level load, etc.)
- Source of the value (file, calculation, default)
- Loading/parsing logic
- Where the initialized value is stored

**Format:**
```
INITIALIZATION:
Set during [phase] when [event occurs]:
  - [FunctionName] loads [DataSource] and returns:
    * [Variable1] = [description]
    * [Variable2] = [description] ([specific value])
  - Both stored in [StructureName] structure (+[Offset] and +[Offset])
```

---

## SECTION 10: MEMORY LAYOUT

**Purpose:** Show the complete memory organization for arrays or multi-entry data.

**Contents:**
- Total memory size calculation
- Entry-by-entry address ranges
- Visual representation of memory organization
- Address boundaries for each entry

**Format:**
```
MEMORY LAYOUT:
With [VariableName] = [Value]:
  Total table size = [Count] * [EntrySize] = [TotalBytes] bytes ([HexSize])
  
  Entry 0: [BaseAddress] + [StartOffset] to [EndOffset]
  Entry 1: [BaseAddress] + [StartOffset] to [EndOffset]
  Entry 2: [BaseAddress] + [StartOffset] to [EndOffset]
  ...
  Entry N: [BaseAddress] + [StartOffset] to [EndOffset]
```

---

## SECTION 11: BOUNDS CHECKING PATTERN

**Purpose:** Document the standard pattern for safe access to prevent buffer overruns.

**Contents:**
- Step-by-step validation algorithm
- Bounds comparison logic
- Success case handling
- Failure case handling
- Return values for each case

**Format:**
```
BOUNDS CHECKING PATTERN:
All functions that access [DataType] follow this pattern:
  1. Check [LowerBoundCondition]
  2. Check [UpperBoundCondition]
  3. If valid: [SuccessAction]
  4. If invalid: [FailureAction]
```

---

## SECTION 12: ERROR HANDLING

**Purpose:** Document how code handles invalid access attempts.

**Contents:**
- Return values for error conditions
- Default values used on failure
- Function-by-function error behavior
- Safety mechanisms

**Format:**
```
ERROR HANDLING:
Functions return [ErrorValue] for out-of-bounds access:
  - [FunctionName] returns [Value] if [condition]
  - [FunctionName] sets [Variable] = [Value] if [condition]
  - [FunctionName] skips [action] if [condition]
```

---

## SECTION 13: USE CASES

**Purpose:** List specific gameplay/system scenarios where this variable is used.

**Contents:**
- Numbered list of concrete use cases
- Game mechanics that depend on this variable
- Player-visible features affected
- System interactions

**Format:**
```
USE CASES:
1. [UseCase1] ([description])
2. [UseCase2] ([description])
3. [UseCase3] ([description])
4. [UseCase4] ([description])
5. [UseCase5] ([description])
```

---

## SECTION 14: CROSS-REFERENCE SUMMARY

**Purpose:** List all code locations that reference this variable.

**Contents:**
- Complete list of addresses where variable is accessed
- Function name if known
- Brief description of what that reference does
- Access type indicator (R=Read, W=Write, *=Both)

**Format:**
```
CROSS-REFERENCE SUMMARY ([Count] locations):
- [Address]: [Description of usage]
- [Address]: [Description of usage]
- [Address]: [Description of usage]
...
- [Address]: [Description of usage]
```

---

## SECTION 15: SOURCE REFERENCE

**Purpose:** Trace the ultimate origin of this variable's data.

**Contents:**
- External file source if applicable
- Loading function name and address
- Data format (txt, bin, dat, etc.)
- Storage location in final structure

**Format:**
```
SOURCE REFERENCE:
Loaded from [DataSource] via [LoaderFunction]
Stored in [StructureName] structure at offset +[Offset]
```

---

## SECTION 16: XREF COUNT AND DETAILS

**Purpose:** Provide the complete Ghidra cross-reference output.

**Contents:**
- Exact copy of Ghidra's XREF annotation
- All addresses with access type (R/W/*)
- Function names where available
- Maintains original formatting

**Format:**
```
XREF COUNT: [Number] locations across [system description]

[VariableName]    XREF[Count]:    [FunctionName]:[Address] ([AccessType]),
                                  [FunctionName]:[Address] ([AccessType]),
                                  [FunctionName]:[Address] ([AccessType]),
                                  ...
```

---

## FOOTER: Ghidra Memory Dump

**Purpose:** Include the raw memory view from Ghidra for reference.

**Contents:**
- Exact address
- Raw bytes in hex
- Data type annotation
- Interpreted value

**Format:**
```
[Address] [Byte1] [Byte2] [Byte3] [Byte4]    [Type]    [InterpretedValue]
```

**Example:**
```
6fdf0aa0 07  00  00  00    DWORD               7h
```

---

## TEMPLATE USAGE GUIDELINES

### When to Use This Template
- Documenting global variables
- Documenting structure fields accessed globally
- Documenting array size variables
- Documenting configuration values
- Any data requiring comprehensive reverse engineering documentation

### Section Priority
**Essential (always include):**
- Header
- Type Information
- Purpose
- Usage Patterns
- Cross-Reference Summary

**Recommended (include when applicable):**
- Location in Global Structure (if part of larger structure)
- Typical Values (if value has meaning)
- Related Structure Definition (if references array/table)
- Access Formula (if used for indexing)
- Memory Layout (if array or table)

**Optional (include when relevant):**
- Bounds Checking Pattern (if safety-critical)
- Error Handling (if complex error behavior)
- Use Cases (for clarity on game impact)
- Source Reference (if loaded from external file)

### Documentation Best Practices
1. **Be Specific:** Use exact addresses, function names, and values
2. **Include Context:** Show surrounding code/data for clarity
3. **Show Examples:** Provide concrete calculations with real values
4. **Cross-Reference:** Link to related variables and functions
5. **Stay Current:** Update when discovering new xrefs or usage patterns
6. **Use Real Code:** Include actual decompiled pseudocode, not generic templates
