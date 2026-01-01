# Hungarian Notation Reference Guide

This document defines the authoritative rules for Hungarian notation type prefixes, type normalization, and type-to-prefix synchronization used throughout Ghidra reverse engineering documentation. These rules apply equally to local function-scoped variables and global data items.

## Type Normalization: Converting Uppercase to Lowercase Builtin Types

Before setting types and applying Hungarian notation, you must first normalize all uppercase Windows SDK types to lowercase builtin types to ensure consistency and leverage Ghidra's builtin type prioritization.

### Why Type Normalization Matters

Ghidra's type resolution system (`resolveDataType` method) searches for types in this priority order:
1. **First**: Root builtin types (e.g., `/uint`, `/ushort`, `/byte`)
2. **Second**: Lowercase variants of builtin types
3. **Third**: Category-based types (e.g., `/WinDef.h/UINT`, `/WinDef.h/USHORT`)

By normalizing to lowercase builtins, you ensure:
- ✅ Builtin type system takes precedence over Windows SDK types
- ✅ Consistent type naming across the entire codebase
- ✅ Alignment with Ghidra's internal type prioritization logic
- ✅ Predictable type resolution behavior

### Normalization Mapping

When examining variable types (from `get_function_variables` for locals or `list_data_items` for globals), apply these conversions:

| Uppercase Windows Type | Lowercase Builtin Type | Size | Notes |
|------------------------|------------------------|------|-------|
| UINT | uint | 4 bytes | Unsigned 32-bit integer |
| USHORT | ushort | 2 bytes | Unsigned 16-bit integer |
| DWORD | uint | 4 bytes | typedef'd as unsigned long (4 bytes) |
| BYTE | byte | 1 byte | Unsigned 8-bit integer |
| WORD | ushort | 2 bytes | Unsigned 16-bit integer |
| BOOL | bool | 1 byte | Boolean type |
| CHAR | char | 1 byte | Signed or unsigned character |
| SHORT | short | 2 bytes | Signed 16-bit integer |
| INT | int | 4 bytes | Signed 32-bit integer |
| LONG | long | 4 bytes | Signed 32-bit long |
| ULONG | ulong | 4 bytes | Unsigned 32-bit long |
| ULONGLONG | ulonglong | 8 bytes | Unsigned 64-bit integer |
| LONGLONG | longlong | 8 bytes | Signed 64-bit integer |

### When to Apply Normalization

**Always** use lowercase builtin type names when:
- Setting local variable types with `set_local_variable_type`
- Setting global data types with `apply_data_type`
- Creating structure field types with `create_struct`
- Documenting types in comments and plate comments

**Never** use uppercase Windows SDK types in type-setting operations.

## Definitive Type-to-Prefix Mapping Table

This table defines the authoritative mapping between Ghidra types and Hungarian notation prefixes. The Hungarian prefix **MUST** match the Ghidra type exactly.

| Ghidra Type | Size | Hungarian Prefix | Example Local Variable | Example Global Variable | Notes |
|-------------|------|------------------|------------------------|-------------------------|-------|
| byte | 1 byte | b or by | bFlags, byStatus | g_bInitialized, g_byControlByte | 8-bit unsigned integer |
| char | 1 byte | c or ch | cCharacter, chNextByte | g_cDelimiter | 8-bit character (signed or unsigned) |
| bool | 1 byte | f | fIsValid, fEnabled | g_fServiceRunning | Boolean flag (use f not b) |
| short | 2 bytes | n or s | nOffset, sTemperature | g_nErrorCount | 16-bit signed integer |
| ushort | 2 bytes | w | wStatus, wPort | g_wServiceStatus | 16-bit unsigned integer (WORD) |
| int | 4 bytes | n or i | nCount, iIndex | g_nActiveConnections | 32-bit signed integer |
| uint | 4 bytes | dw | dwFlags, dwTableIndex | g_dwProcessId, g_dwFlags | 32-bit unsigned integer (DWORD) |
| long | 4 bytes | l | lOffset | g_lFilePosition | 32-bit signed long |
| ulong | 4 bytes | dw | dwValue | g_dwTickCount | 32-bit unsigned long (same as DWORD) |
| longlong | 8 bytes | ll | llTimestamp | g_llStartTime | 64-bit signed integer |
| ulonglong | 8 bytes | qw | qwBitPattern | g_qwTotalBytes | 64-bit unsigned integer (QWORD) |
| float | 4 bytes | fl | flScale | g_flScaleFactor | 32-bit floating point |
| double | 8 bytes | d | dPowerResult | g_dPiConstant | 64-bit floating point |
| float10 | 10 bytes | ld | ldExtendedPrecision | g_ldMathConstant | 80-bit extended precision float |
| void * | 4 bytes | p | pBuffer, pData | g_pSharedMemory | Generic pointer (32-bit) |
| \<type\> * | 4 bytes | p\<Type\> | pUnitAny, pFileHandle | g_pCurrentPlayer | Typed pointer (use structure name) |
| HANDLE | 4 bytes | h | hFile, hThread | g_hServiceHandle, g_hRegistryKey | Win32 handle types (HANDLE, HKEY, etc.) |
| byte[N] | N bytes | ab | abXmmBuffer, abTempStorage | g_abEncryptionKey | Array of bytes |
| ushort[N] | N*2 bytes | aw | awTableEntries | g_awPortNumbers | Array of words |
| uint[N] | N*4 bytes | ad | adOffsetTable | g_adPlayerSlots | Array of dwords |
| char[] | varies | sz | szFilename, szErrorMessage | g_szConfigPath, szModuleName | Null-terminated string (no pointer) |
| char * | 4 bytes | sz | szPath | g_szRegistryPath | Null-terminated string pointer |
| char * | 4 bytes | lpsz | lpszCommandLine | g_lpszServiceName | Long pointer to string (legacy) |
| wchar_t * | 4 bytes | wsz | wszUnicodePath | g_wszDisplayName | Wide string pointer |
| \<Structure\> | varies | \<StructName\> | unitAny, playerData | g_ServiceStatus, CurrentGameState | Structure types (no prefix, camelCase) |
| Function ptr | 4 bytes | \<FunctionName\> | N/A (locals rare) | ProcessInputEvent, ValidatePacket | Function pointers (PascalCase, no prefix) |

### Scope Prefix for Global Variables

All global variables **MUST** be prefixed with `g_` before the type prefix:

| Type | Local Variable | Global Variable |
|------|----------------|-----------------|
| uint | dwFlags | g_dwFlags |
| ushort | wStatus | g_wServiceStatus |
| byte | bInitialized | g_bInitialized |
| byte[16] | abXmmBuffer | g_abEncryptionKey |
| char * | szFilename | g_szConfigPath |
| Structure | unitAny | g_CurrentGameState |

**Exception**: String constants may omit `g_` if they are true read-only constants rather than mutable data (e.g., `szErrorMessage` instead of `g_szErrorMessage`).

## Type-to-Prefix Consistency Verification

After completing all variable renames, you **MUST** perform a type-to-prefix consistency verification to ensure that Hungarian notation prefixes accurately reflect the actual Ghidra types.

### Verification Process

1. **Retrieve current variable types**:
   - For locals: Use `get_function_variables` to see current types
   - For globals: Use `get_type_size` or inspect with data type tools

2. **Compare prefix against type**:
   - If type is `uint`, prefix must be `dw`
   - If type is `ushort`, prefix must be `w`
   - If type is `byte`, prefix must be `b` or `by`
   - If type is `ulonglong`, prefix must be `qw`
   - If type is `double`, prefix must be `d`

3. **Identify mismatches**:
   - Mismatch indicates either incorrect type assignment OR incorrect prefix choice
   - Both must be corrected to maintain documentation accuracy

4. **Common Mismatch Examples**:
   - ❌ Type `uint` with prefix `b` → Should be `dw` (4 bytes, not 1 byte)
   - ❌ Type `ushort` with prefix `dw` → Should be `w` (2 bytes, not 4 bytes)
   - ❌ Type `UINT` (uppercase) with any prefix → Normalize to `uint` first
   - ❌ Type `undefined4` with prefix `p` → Set proper type first (uint/int/float/pointer)

### Verification Examples

**Correct Synchronization**:
```
Type: uint        → Prefix: dw  → Variable: dwTableIndex        ✅
Type: ushort      → Prefix: w   → Variable: wExponentMask       ✅
Type: byte[16]    → Prefix: ab  → Variable: abXmmBuffer         ✅
Type: ulonglong   → Prefix: qw  → Variable: qwPackedDoubleBits  ✅
Type: double      → Prefix: d   → Variable: dPowerResult        ✅
```

**Incorrect Synchronization (Must Fix)**:
```
Type: uint        → Prefix: u   → Variable: uMantissaShift      ❌ (should be dw)
Type: undefined4  → Prefix: p   → Variable: pTempFloat2         ❌ (not a pointer!)
Type: UINT        → Prefix: dw  → Variable: dwFlags             ❌ (normalize to uint)
Type: ushort      → Prefix: dw  → Variable: dwStatus            ❌ (should be w)
```

## Setting Types Before Renaming

For both local and global variables, you **MUST** set the correct type before applying Hungarian notation. This ensures that:
- Hungarian notation prefixes align with Ghidra's internal type information
- Decompilation quality improves
- Code becomes more understandable
- Cross-references reflect accurate type information

### Type Replacement Rules

Replace undefined types with proper lowercase builtin types:

| Undefined Type | Replace With | Based On |
|----------------|--------------|----------|
| undefined1 | byte | 8-bit unsigned values |
| undefined1 | char | 8-bit character data |
| undefined1 | bool | Boolean flags |
| undefined2 | ushort | 16-bit unsigned values |
| undefined2 | short | 16-bit signed values |
| undefined4 | uint | 32-bit unsigned integers |
| undefined4 | int | 32-bit signed integers |
| undefined4 | float | 32-bit floating point |
| undefined4 | \<type\> * | 32-bit pointers (specify pointed-to type) |
| undefined8 | double | 64-bit floating point |
| undefined8 | ulonglong | 64-bit unsigned integers |
| undefined8 | longlong | 64-bit signed integers |
| undefined1[N] | byte[N] | Byte arrays (XMM spills, buffers) |
| undefined2[N] | ushort[N] or word[N] | Word arrays |
| undefined4[N] | uint[N] or dword[N] | Dword arrays |

### Pointer Type Specification

For pointer types, always specify the **complete pointer declaration** including the pointed-to type:

| Incorrect | Correct | Notes |
|-----------|---------|-------|
| pointer | void * | Generic pointer |
| pointer | char * | String pointer |
| pointer | float10 * | Typed pointer to float10 |
| pointer | UnitAny * | Typed pointer to structure |

### Type-Setting Examples

**Local Variables** (use `set_local_variable_type`):
```
Variable: local_c     Type: UINT          → Set to: uint         → Rename: dwFlags
Variable: local_10    Type: undefined4    → Set to: void *       → Rename: pBuffer
Variable: local_8     Type: undefined4    → Set to: int          → Rename: nCount
Variable: local_14    Type: USHORT        → Set to: ushort       → Rename: wStatus
Variable: local_20    Type: undefined1[16]→ Set to: byte[16]     → Rename: abXmmBuffer
```

**Global Variables** (use `apply_data_type`):
```
Global: DAT_6fb7c940  Type: undefined4    → Set to: uint         → Rename: g_dwProcessId
Global: DAT_6fb7c950  Type: undefined8    → Set to: ulonglong    → Rename: g_qwBitMask
Global: DAT_6fb7c960  Type: undefined1[32]→ Set to: byte[32]     → Rename: g_abEncryptionKey
Global: DAT_6fb7c980  Type: undefined4    → Set to: char *       → Rename: g_szConfigPath
```

## Complete Workflow Example

This example demonstrates the complete type normalization, type setting, and Hungarian notation process:

### Step 1: Discover Variables
```
get_function_variables() returns:
- local_c: UINT (uppercase)
- local_10: undefined4
- local_14: USHORT (uppercase)
- local_18: undefined1[16]
```

### Step 2: Normalize Types
```
local_c: UINT → uint (lowercase)
local_10: undefined4 → (analyze usage to determine correct type)
local_14: USHORT → ushort (lowercase)
local_18: undefined1[16] → byte[16] (lowercase)
```

### Step 3: Set Types
```
set_local_variable_type("local_c", "uint")      # Not UINT!
set_local_variable_type("local_10", "void *")   # Based on usage
set_local_variable_type("local_14", "ushort")   # Not USHORT!
set_local_variable_type("local_18", "byte[16]") # Not BYTE[16]!
```

### Step 4: Apply Hungarian Notation
```
Type: uint      → Prefix: dw → Rename: local_c → dwFlags
Type: void *    → Prefix: p  → Rename: local_10 → pBuffer
Type: ushort    → Prefix: w  → Rename: local_14 → wStatus
Type: byte[16]  → Prefix: ab → Rename: local_18 → abXmmBuffer
```

### Step 5: Verify Consistency
```
dwFlags: Type uint ✅ Prefix dw ✅ → Synchronized
pBuffer: Type void * ✅ Prefix p ✅ → Synchronized
wStatus: Type ushort ✅ Prefix w ✅ → Synchronized
abXmmBuffer: Type byte[16] ✅ Prefix ab ✅ → Synchronized
```

## Summary of Key Principles

1. **Always normalize uppercase types to lowercase builtins** before setting types
2. **Always set types before renaming** to ensure prefix accuracy
3. **Use the mapping table as authoritative reference** for type-to-prefix mapping
4. **Verify type-to-prefix consistency** after all renames complete
5. **Global variables require g_ prefix** before the type prefix
6. **Structure types use camelCase without type prefix** (the name IS the type)
7. **Mismatches indicate errors** that must be corrected for accuracy

These rules ensure consistent, accurate, and maintainable Hungarian notation throughout the Ghidra reverse engineering documentation.
