# ENHANCED REVERSE ENGINEERING PROMPT FOR GHIDRA DATA ANALYSIS

Analyze current cursor position, identify data type, apply Hungarian notation names based on usage patterns.

## 🚨 CRITICAL REQUIREMENTS

### 1. MANDATORY Hungarian Notation
**ALL names MUST use type prefixes:** `szPlayerName`, `pEntries`, `dwFlags` (NOT `PlayerName`, `Entries`, `Flags`)
See **Hungarian Notation Reference** below.

### 2. MANDATORY Silent Operation
**Work silently without status output.**
**Only output:** Final analysis summary or error messages if operations fail.

### 3. MANDATORY Next Selection Workflow
**When all work is completed on the current selection:**
1. Say: To continue enter "Cursor is at next location continue the analysis"

---

## Analysis Workflow

### Step 0: Verify Existing Documentation (Always First!)

**Check if current data already has template-compliant documentation:**
1. Call `get_current_address()` to get address
2. **CRITICAL:** Call `analyze_data_region(address)` to get `current_name` and `current_type`
3. **CRITICAL:** Retrieve PRE comment by decompiling a function that references this address, OR by checking if comment exists
   - For now, there's no direct "get_comment" API, so we check during decompilation or assume missing
   - **If no way to retrieve comment exists, assume it needs to be set**
4. **Validate template compliance (only if comment was retrieved):**
   - Has "TYPE:" section? ✓
   - Has "VALUE:" section? ✓
   - Has "PURPOSE:" section? ✓
   - Follows template structure with header banner? ✓

**If ALL checks pass:**
- Documentation is complete and template-compliant
- Output: "Data already documented following template. To continue enter 'Cursor is at next location continue the analysis'"
- **Skip Steps 1-7**

**If ANY check fails OR comment cannot be retrieved:**
- Continue to Step 1 below
- Must document using proper template format in Step 6

**Starting Point Optimization:**
- **Data has type + descriptive name?** → Skip to Step 4 (refine fields if structure), then Step 5
- **Data has type but generic name (DAT_\*)?** → Skip to Step 3 (rename), then Step 4-5 if structure
- **Undefined data?** → Start at Step 1

---

### Step 1: Identify Data Region
Call `get_current_address()` then `analyze_data_region()` to get boundaries, xrefs, and type hints.

### Step 2: XRef Analysis
- **Primitives (1-8 bytes):** Use `get_bulk_xrefs()` for all byte addresses
- **Structures (>16 bytes):** Sample at DWORD boundaries (every 4 bytes) to avoid timeout. Max 100 addresses.
- Identify field boundaries from xref offsets and multi-byte access patterns.
- **Decompilation:** Use `batch_decompile_xref_sources(target_address, limit=2, offset=0)` to avoid token overflow
  - If more context needed, paginate: `limit=2, offset=2`, then `limit=2, offset=4`, etc.
  - For high-traffic globals (50+ xrefs), limit=2 is critical to stay under 25,000 token response limit

### Step 3: Apply Type (Two-Step Reliable Pattern)

**Best Practice - Use separate calls (avoids retry loops):**

```python
# Step 3a: Apply the data type first
apply_data_type(address, "dword")  # or "char[N]", "pointer", etc.

# Step 3b: Rename with Hungarian notation
rename_or_label(address, "dwName")  # or "szString", "pPointer", etc.

# Step 3c: Set documentation (done in Step 6)
set_decompiler_comment(address, "formatted_documentation")
```

**Type Names (use directly with apply_data_type):**
- Primitives: `"dword"`, `"word"`, `"byte"`, `"int"`, `"short"`, `"char"`, `"float"`, `"double"`, `"pointer"`, `"qword"`, `"longlong"`
- Strings: `"char[N]"` (where N is the size, e.g., `"char[6]"`, `"char[256]"`)
- Arrays: `"dword[64]"`, `"byte[16]"`, `"pointer[32]"`, etc.
- Booleans: `"bool"`

**Verify Success:**
- `apply_data_type()` returns success message with size info
- `rename_or_label()` confirms rename succeeded
- Verify data type is no longer "undefined" using `analyze_data_region()`
- Verify name has Hungarian notation prefix

### Step 4: Structure Field Analysis (if applicable)

**For structures and arrays only:**
- `analyze_struct_field_usage(address, max_functions=10)` - Get access patterns and name suggestions
- `get_field_access_context(struct_address, field_offset)` - See specific field usage examples
- `search_data_types(pattern)` - Search for structures by name pattern
- `list_data_types(category)` - List data types by category
- `modify_struct_field(struct_name, field_name, new_type, new_name)` - Update individual fields

**Verify each field:**
- All fields have Hungarian notation names
- No undefined gaps - padding fields for unknowns (`_1`, `_2`, etc.)
- Field types match usage patterns from xrefs

**Field Pattern Guide:**
| Code Pattern | Type | Name Examples |
|--------------|------|---------------|
| `if (x->field == 0)` | Boolean/flag | `fEnabled`, `bActive` |
| `x->field++` | Counter | `nCount`, `dwIndex` |
| `CMP field, N` | Threshold | `dwMaxSize`, `nThreshold` |
| `ptr = x->field; [ptr]` | Pointer | `pData`, `pNext` |
| `x->field[i]` | Array | `szName[N]`, `pEntries[N]` |
| Always same value | Padding | `_1`, `_2[0x158]` |

### Step 5: Gather Documentation Data

**Collect information for template:**
1. **TYPE:** Already applied in Step 3 (e.g., "DWORD", "MyStruct", "byte[64]")
2. **VALUE:** Retrieve current value from memory
   - For primitives: Use `inspect_memory_content(address, length)` to see hex dump
   - For initialized data: Document current hex and decimal values
   - For uninitialized: Note "Uninitialized" or default value
3. **PURPOSE:** Synthesize from XRef analysis (Step 2) and usage patterns
4. **Additional sections:** Based on findings (XREF COUNT, USAGE PATTERN, etc.)

### Step 6: Set Documentation Comment

After gathering all documentation data:
1. **Format documentation** using the **Documentation Template** below
2. **Set PRE comment** at the data address with the formatted documentation
   - Use `set_decompiler_comment(address, formatted_documentation)` for PRE comment
   - This is called AFTER Steps 3a-3b (apply type and rename)

**Code Pattern:**
```python
# After apply_data_type() and rename_or_label() succeed:
set_decompiler_comment(address, """================================================================================
                    STRING szVideoSection @ 0x0040BC08
================================================================================
TYPE: char[6] (6 bytes) - Null-terminated ASCII string

VALUE: "VIDEO" (0x56 0x49 0x44 0x45 0x4F 0x00)

PURPOSE:
[Your detailed description here...]
""")
```

All documentation MUST follow the template structure with mandatory TYPE, VALUE, and PURPOSE sections.

**Verify Documentation Set:**
- `set_decompiler_comment()` returns success message
- PRE comment is visible at address in Ghidra
- Comment follows template format with header banner (====...)
- All mandatory sections present: TYPE, VALUE, PURPOSE
- Any additional sections based on findings are included

### Step 7: Output Final Summary

**Provide concise summary of completed work:**
- Address analyzed
- Type applied (with name)
- Key findings (purpose, xref count, relationships)
- Documentation status: "✓ Complete"

**Then output:** "To continue enter 'Cursor is at next location continue the analysis'"

---

## Hungarian Notation (MANDATORY)

**Type Prefix Decision Tree:**
| Type | Prefix | When to Use | Examples |
|------|--------|-------------|----------|
| **Boolean** | `f` | Function-level flags, status variables | `fEnabled`, `fIsActive`, `fHasData` |
| **Boolean** | `b` | Struct field booleans, byte-sized flags | `bActive`, `bVisible`, `bLocked` |
| **String (ASCII)** | `sz` | Null-terminated char[] | `szPlayerName`, `szGameName` |
| **String (Unicode)** | `w`, `wsz` | Null-terminated wchar_t[] | `wName`, `wszTitle` |
| **Pointer (modern)** | `p` | General pointers, struct pointers | `pData`, `pNext`, `pPlayerData` |
| **Pointer (legacy)** | `lp` | Windows API compatibility | `lpBuffer`, `lpStartAddress` |
| **DWORD/32-bit** | `dw` | Unsigned 32-bit integers | `dwFlags`, `dwCount`, `dwUnitId` |
| **WORD/16-bit** | `w` | Unsigned 16-bit integers | `wX`, `wY`, `wPort` |
| **int/signed** | `n` | Signed integers, counts, indices | `nCount`, `nIndex`, `nOffset` |
| **byte/8-bit** | `b`, `by` | Unsigned bytes | `bValue`, `byOpcode` |
| **Function ptr** | `fn` | Function pointers | `fnCallback`, `fnHandler` |
| **Handle** | `h` | Windows handles | `hFile`, `hThread`, `hModule` |
| **Size/count of bytes** | `cb` | Byte counts, buffer sizes | `cbSize`, `cbBuffer` |
| **Array** | `a` + type | Arrays with count suffix | `adwValues`, `aszNames` |

**Patterns:** Position(`dwPosX/Y`,`nX/Y`), Size(`dwSizeX/Y`,`cbSize`), Count(`dwCount`,`nCount`,`wCount`), Lists(`pNext`,`pFirst`,`pLast`), Flags(`dwFlags`,`fEnabled`), IDs(`dwUnitId`,`nId`), Reserved(`_1`,`_2[0x158]`)

**Suffixes:** Count/Size/Length/Num, X/Y/Z/Pos/Offset, State/Mode/Status/Flags, Id/Index/No/Type

**Example - UnitAny struct:** `dwType`, `dwTxtFileNo`, `dwUnitId`, `dwMode`, `pPlayerData`, `pPath`, `pStats`, `pInventory`, `wX`, `wY`, `dwFlags`

**Example - GameStructInfo struct:** `_1[0x1B]`, `szGameName[0x18]`, `szGameServerIp[0x56]`, `szAccountName[0x30]`, `szCharName[0x18]`, `_2[0x158]`, `szGamePassword[0x18]`

---

## Data Type Mapping

**Unsigned Integer Types:**
- `uint8_t`, `BYTE`, `unsigned char` → `"byte"` (8-bit, range 0-255)
- `uint16_t`, `WORD`, `unsigned short` → `"word"` (16-bit, range 0-65535)
- `uint32_t`, `DWORD`, `unsigned int` → `"dword"` (32-bit, range 0-4294967295)
- `uint64_t`, `QWORD`, `unsigned long long` → `"qword"` (64-bit)

**Signed Integer Types:**
- `int8_t`, `char`, `signed char` → `"char"` (8-bit, range -128 to 127)
- `int16_t`, `short`, `signed short` → `"short"` (16-bit, range -32768 to 32767)
- `int32_t`, `int`, `long` (Win32) → `"int"` (32-bit, range -2147483648 to 2147483647)
- `int64_t`, `long long` → `"longlong"` (64-bit)

**Floating Point Types:**
- `float` → `"float"` (32-bit IEEE 754)
- `double` → `"double"` (64-bit IEEE 754)

**Pointer Types:**
- `T*` (any pointer) → `"pointer"` (32-bit on x86, 64-bit on x64)
- `void*` → `"pointer"`
- Function pointers → `"pointer"` (document signature in comment)

**Boolean Types:**
- `bool` (C++) → `"bool"` (1 byte in practice, but compiler-dependent)
- `BOOL` (Win32) → `"int"` (typedef for int, 4 bytes)

**Character String Types:**
- `char[N]` (ASCII/ANSI) → `"char[N]"` or `"byte[N]"` (null-terminated)
- `wchar_t[N]` (UTF-16 on Windows) → `"wchar_t[N]"` or `"word[N]"` (null-terminated)
- `char16_t[N]` (C++11 UTF-16) → `"word[N]"`
- `char32_t[N]` (C++11 UTF-32) → `"dword[N]"`

**Array Types:**
- `T[N]` (fixed-size array) → `"<type>[N]"` where type matches element
- `BYTE[N]`, `unsigned char[N]` → `"byte[N]"`
- `WORD[N]`, `uint16_t[N]` → `"word[N]"`
- `DWORD[N]`, `uint32_t[N]` → `"dword[N]"`
- `void*[N]`, `T*[N]` → `"pointer[N]"` (array of pointers)

**Common Windows Types:**
- `HANDLE`, `HMODULE`, `HWND` → `"pointer"` (opaque handle types)
- `SIZE_T`, `ULONG_PTR`, `DWORD_PTR` → `"pointer"` on x64, `"dword"` on x86
- `LPVOID`, `PVOID` → `"pointer"` (void* equivalent)
- `LPSTR`, `PSTR` → `"pointer"` (char* pointer, not array)
- `LPWSTR`, `PWSTR` → `"pointer"` (wchar_t* pointer)

**Padding and Alignment:**
- Unknown/reserved bytes → `"byte[0xN]"` (use hex size for clarity)
- Alignment padding → `"byte[N]"` (document alignment requirement in comment)

**Best Practices:**
1. **Prefer sized types:** Use `int32_t` equivalents over `int` for cross-platform clarity
2. **Sign matters:** Use `"int"` for signed, `"dword"` for unsigned (affects comparisons, arithmetic)
3. **String encoding:** ASCII→`char[]`, Unicode→`wchar_t[]` (document encoding in comment)
4. **Pointer sizes:** Document target architecture (x86 vs x64) for pointer-sized types
5. **Enums:** Use underlying type (`"int"` or `"dword"`) and document values in comment
6. **Bitfields:** Use underlying type (`"byte"`, `"word"`, `"dword"`) and document bit layout in comment

---

## Implementation Rules

**Rule 1:** ALL names need type prefixes. `szPlayerName` not `PlayerName`, `dwCount` not `Count`.

**Rule 2:** Analyze usage before finalizing. Extract names from decompiled code.

**Rule 3:** Verify: `result.current_type != "undefined"` and `result.current_name != "DAT_*"`

**Rule 4:** Prefer explicit sizes in hex for padding: `_2[0x158]` over `_2[344]`

**Rule 5:** Use sequential numbering for unknown fields: `_1`, `_2`, `_3` (NOT `Unknown1`, `Unk2`, `Reserved3`)

---

## Common Pitfalls

**Critical Mistakes to Avoid:**

1. **Missing type prefixes:** Use `dwCount` not `Count`, `szName` not `Name`, `pData` not `Data`
2. **Inconsistent padding:** Use sequential `_1`, `_2`, `_3` (NOT `Unknown1`, `Unk2`, `Reserved3`)
3. **Unverified structures:** Always run `get_bulk_xrefs()` before creating fields - gaps become padding
4. **Generic pointer names:** Use `pPlayerData` not `pData` (document unions in comments)
5. **Wrong string prefixes:** Use `szName` for ASCII, `wName` for Unicode (type matches prefix)
6. **Decimal padding sizes:** Use hex `_1[0x158]` not `_1[344]` (matches offset calculations)
7. **Using atomic create_and_apply_data_type():** This tool has type parameter issues - use separate `apply_data_type()` + `rename_or_label()` instead
8. **Fetching xrefs for every byte:** Sample at field boundaries (4/8-byte intervals), not every byte in large structures
9. **Skipping validation:** Always use `validate_data_type_exists()` before `apply_data_type()` to catch typos
10. **Forgetting to set documentation comment:** Always call `set_decompiler_comment()` after applying type and name

**Best Practices:**
- Hungarian notation mandatory for ALL names
- Verify field boundaries with xrefs
- Document unions via comments (Ghidra limitation)
- Let decompiled code guide naming (analyze before finalizing)

---

## Advanced Pattern Reference

See these D2Structs.h patterns for complex scenarios:

**Simple Structures:** TargetInfo (basic fields with pointers)
**Padding:** GameStructInfo (reserved bytes with hex sizes)
**Nested Structures:** UnitAny (component structures referenced in parent)
**Unions:** Document overlapping fields in comments (Ghidra doesn't support native unions)
**Pointer Arrays:** Room2 (pRoom2Near - dynamic array with count field)
**String Buffers:** LevelTxt (mix of ASCII char[] and Unicode wchar_t[])
**Linked Lists:** RosterUnit (pNext pointer pattern)
**Bitfields:** MonsterData (document bit layout in comments)

For detailed examples of these patterns, refer to the structure definitions in the Hungarian Notation Reference section above.

---

## Documentation Template
```
================================================================================
                          [TYPE] [Name] @ [Address]
================================================================================
TYPE: [DataType] ([Size]) - [Desc]
VALUE: [Hex] ([Dec])

PURPOSE:
[What it represents and primary usage in 1-2 sentences]

SOURCE REFERENCE: [REQUIRED IF data is loaded from file]
Loaded from [FileName.txt] via [LoaderFunction], stored in [StructureName] at +[Offset]
Examples: ItemTypes.txt, Levels.txt, Monsters.txt, etc.

[ADDITIONAL SECTIONS AS NEEDED:]
Add relevant sections based on analysis findings:
(NOTE: Hungarian notation is mandatory for naming - do not document it separately here)
- RELATED GLOBALS: List of related addresses with offsets and relationships
- INITIALIZATION: [Function] @ [Addr] sets this during [when] from [source]
- TYPICAL VALUE: What common/expected values mean in context
- STRUCTURE LAYOUT: For pointers to arrays/structs, document the entry size and key field offsets
- USAGE PATTERN: Detailed breakdown of how the data is accessed across functions
- ARRAY ACCESS FORMULA: Mathematical formula for calculating array element addresses
- MEMORY LAYOUT: Visual representation of memory structure and entry boundaries
- BOUNDS CHECKING PATTERN: Standard validation pattern used across functions
- ERROR HANDLING: How functions handle invalid values or out-of-bounds access
- USE CASES: Specific scenarios where this data is critical
- XREF COUNT: Total number of references and key function names
- LOCATION: Part of [Struct] at +[Offset] (for structure fields)
- CONSTRAINTS: Value ranges, validation rules, boundary conditions
- ALGORITHMS: Calculation methods, transformation logic, encoding schemes
- PERFORMANCE: Caching behavior, hot paths, optimization opportunities
- SECURITY: Input validation, bounds checking, sanitization
- EDGE CASES: Special values, error conditions, fallback behavior
- DEPENDENCIES: Required initialization order, external resources
- EXAMPLES: Concrete usage examples from decompiled code
- etc.
```

## Completion Checklist

**BEFORE reporting completion, verify ALL of the following:**

### Type & Naming Requirements:
- ✓ Data type is NO LONGER "undefined" (verify with `analyze_data_region`)
- ✓ Name has Hungarian notation prefix (dw/p/sz/n/w/b/h/fn/etc.)
- ✓ Name is descriptive, NOT generic (NOT "DAT_*")
- ✓ For structures: All fields have Hungarian notation names
- ✓ For structures: Padding uses `_1`, `_2`, `_3` format (NOT `Unknown1`, `Unk2`)
- ✓ For structures: No undefined gaps - all bytes accounted for

### Documentation Requirements (MANDATORY - DO NOT SKIP):
- ✓ **PRE comment was SET using `set_decompiler_comment(address, documentation)`**
- ✓ **Comment has header banner (====...)**
- ✓ **Comment has "TYPE:" section with data type and size**
- ✓ **Comment has "VALUE:" section with hex and decimal values**
- ✓ **Comment has "PURPOSE:" section explaining usage**
- ✓ **Comment has "SOURCE REFERENCE:" section IF data is loaded from file (ItemTypes.txt, Levels.txt, etc.)**
- ✓ **Comment includes other relevant sections (XREF COUNT, USAGE PATTERN, etc.)**

### Final Verification:
**⚠️ CRITICAL: You MUST call `set_decompiler_comment()` in Step 6 - do not skip this step!**
**If all checks pass:** Output completion summary and prompt for next selection
