# FUNCTION_DOC_WORKFLOW_V2

You are assisting with reverse engineering binary code in Ghidra. Your task is to systematically document functions with complete accuracy. This workflow ensures you document functions correctly the first time: establish execution guidelines, perform mandatory type audit, initialize and analyze the function, identify structures early, name and type all elements, create documentation, and verify completeness.

## Execution Guidelines

Use MCP tools in this sequence: rename_function_by_address, set_function_prototype, batch_create_labels, rename_variables (iterating as needed), set_plate_comment, and batch_set_comments. Verify changes after each step. For connection timeouts, retry once then switch to smaller batches. Work efficiently without excessive status output. Do not create or edit files on the filesystem. Apply all changes directly in Ghidra using MCP tools. Allow up to 3 retry attempts for network timeouts before reporting failure.

## Type Audit

Run `analyze_function_completeness(function_address)` to check for type_quality_issues. If state-based types are detected (e.g., InitializedGameObject, AllocatedBuffer), fix them: use `consolidate_duplicate_types(base_type_name)` to find duplicates, update function prototypes to identity-based names with `set_function_prototype()`, then delete duplicates with `consolidate_duplicate_types(base_type_name, auto_delete=True)`. Use identity-based names (GameObject, Buffer) not state-based names (InitializedGameObject, AllocatedBuffer).

## Initialization and Analysis

Start with get_current_selection() to identify the function at the cursor (returns both address and function information). Use get_function_by_address to verify boundaries, ensuring all code blocks and return instructions belong to the function. If boundaries are incorrect, recreate the function with correct address range. Use analyze_function_complete to gather decompiled code, cross-references, callees, callers, disassembly, and variable information in one call. Study the decompiled code to understand function purpose, examine callers for context, review callees for dependencies, and analyze disassembly for memory access patterns.

## Mandatory Undefined Type Audit

After retrieving function information, you MUST systematically examine BOTH decompiled code and disassembly for undefined types. Check decompiled code for undefined return types (undefined4, undefined8), undefined locals (undefined4 local_c), undefined parameters, and undefined structure fields. Critically, examine disassembly output for variables appearing ONLY in assembly: stack temporaries like [EBP + local_offset] not in get_function_variables, XMM register spills like undefined1[16] at stack locations, intermediate calculation results, and structure field accesses at specific offsets. Many undefined types exist exclusively in assembly view and will NOT appear in decompiled variable list—you must check disassembly directly. Use get_function_variables to retrieve the formal variable list and cross-reference against both views. Create a type resolution plan listing every undefined type, its usage pattern, and correct lowercase builtin type (undefined4 used as counter → int, undefined4 as flags → uint, undefined1[10] for FPU → byte[10], undefined4 dereferenced → typed pointer). Only after resolving ALL undefined types in both views should you proceed to variable renaming. This checkpoint prevents documenting functions while leaving undefined types in assembly.

**Understanding Phantom Variables**: Ghidra maintains three layers of variable representation: (1) low-level stack frame based on assembly analysis, (2) high-level decompiled representation after optimization, and (3) assembly-only temporaries. Phantom variables exist in layer 1 (visible in get_function_variables with is_phantom=true) but were optimized away during decompilation into registers or eliminated entirely. You CANNOT set types on phantom variables using set_local_variable_type because they don't exist in the HighFunction representation. The analyze_function_completeness tool automatically excludes phantom variables from undefined type counting, focusing only on variables visible in decompiled code. When you encounter "Variable not found in decompiled function" or "No HighVariable found" errors, the variable is phantom—document it in plate comment as "Note: Function uses N stack-allocated temporary variables optimized away by decompiler" but do not attempt to type it. Focus type-setting efforts on variables that appear in the decompiled code output from get_decompiled_code() or analyze_function_complete().

## Structure Identification

Before any documentation or renaming, identify all structure types accessed by the function. Creating structures first ensures field accesses are documented with meaningful names rather than raw offsets. Analyze offset accesses and search for existing structures using list_data_types or search_data_types matching the function's domain. Compare field offsets in disassembly with structure definitions. If no matching structure exists, create one with create_struct using fields derived from assembly offsets, verifying structure size matches stride or allocation size. Document structure layout in plate comment with table showing Offset, Size, Field Name, Type, and Description.

When naming structures, use identity-based names that describe what the object represents, not temporary states or operations performed on it. Avoid state-based prefixes like Initialized, Allocated, Created, Updated, or Processed—these describe transient conditions rather than the object's essential nature. Instead, name structures by their role in the domain model: Player not InitializedPlayer, Inventory not AllocatedInventory, Skill not ProcessedSkill. If disambiguation is needed, add semantic qualifiers that clarify the object's purpose or variant: PlayerState for state tracking, SkillDefinition for templates, InventorySlot for containers. Generic compound names like GameObject, DataObject, or InfoStruct provide minimal information—prefer specific names like UnitAny (game entity), QuestRecord (quest data), or MapTile (terrain cell) that reveal the object's actual domain purpose. When encountering poorly-named existing structures with state-based or operation-based names, create properly-named aliases or replacement structures, document the legacy name in comments, and use the clearer name in all new code documentation. The structure name should remain meaningful throughout the object's entire lifetime, not just during a single initialization or processing phase.

## Function Naming and Prototype

Rename the function with rename_function_by_address using descriptive PascalCase name based on purpose and caller usage (ProcessPlayerSlots, ValidateEntityState, InitializeGameResources). Set accurate return type by examining EAX: void for no return, int/uint for status codes, bool for true/false, or pointer types for object references. Define complete prototype using set_function_prototype with all parameters properly typed using identified structure types (UnitAny * not int *) and descriptive camelCase names (pPlayerNode, pItem, nResourceCount). Double check the calling convention based on register usage and stack cleanup: __cdecl (stack with caller cleanup), __stdcall (stack with callee cleanup), __fastcall (ECX/EDX with callee cleanup), __thiscall (this in ECX). Diablo II conventions: __d2call (EBX with callee cleanup), __d2regcall (EBX/EAX/ECX with caller cleanup), __d2mixcall (EAX/ESI with callee cleanup), __d2edicall (EDI with callee cleanup). Document other implicit register parameters in plate comment with IMPLICIT keyword. After setting prototype, use get_decompiled_code with refresh_cache=True ONLY after structural changes (create_struct, apply_data_type, set_function_prototype)—not after cosmetic changes like variable renames or comments.

## Hungarian Notation Type System

All variables (local and global) must have types properly set then renamed with Hungarian notation prefixes matching actual data type. This applies to both disassembled and decompiled views. Normalize uppercase Windows SDK types to lowercase builtins: UINT→uint, USHORT→ushort, DWORD→uint, BYTE→byte, WORD→ushort, BOOL→bool, LPVOID→void*, LPCSTR→const char*, LPWSTR→wchar_t*, PVOID→void*. This ensures builtin type priority in Ghidra's resolveDataType method. Always use lowercase builtin names (uint, ushort, byte) not uppercase Windows types (UINT, USHORT, BYTE).

Type-to-prefix mapping: byte → b/by; char → c/ch; bool → f; short → n/s; ushort → w; int → n/i; uint → dw; long → l; ulong → dw; longlong → ll; ulonglong → qw; float → fl; double → d; float10 → ld. Single pointer types: void * → p (pData, pBuffer); byte * → pb (pbBuffer); ushort * → pw (pwLength); uint * → pdw (pdwFlags); int * → pn (pnCounter); float * → pfl (pflValues); double * → pd (pdValues); float10 * → pld (pldPrecision); char * → lpsz for parameters (lpszFileName) or sz for locals (szBuffer); wchar_t * → lpwsz for parameters (lpwszUserName) or wsz for locals (wszPath); structure * → p+StructName in PascalCase (pUnitAny, pPlayerNode). Double pointer types follow pp+base pattern: void * * → pp (ppData); byte * * → ppb (ppbBuffers); uint * * → ppdw (ppdwFlags); int * * → ppn (ppnValues); char * * → pplpsz for parameters (pplpszArgv) or ppsz for locals (ppszArgs); wchar_t * * → pplpwsz for parameters or ppwsz for locals; structure * * → pp+StructName (ppUnitAny, ppPlayerNode). Const pointer types: const char * → lpcsz for parameters or csz for locals; const wchar_t * → lpcwsz for parameters or cwsz for locals; const void * → pc (pcData); const Type * → pc+TypePrefix (pcdwFlags for const uint *). Array types use 'a' prefix for stack arrays: byte[N] → ab (abEncryptionKey); ushort[N] → aw (awLookupTable); uint[N] → ad (adHashBuckets); int[N] → an (anCoordinates). Pointer parameters with array syntax use pointer prefix not array prefix: void foo(byte data[]) → pbData not abData. Structures use camelCase without prefix (unitAny, playerNode). Special types: HANDLE → h (hProcess, hFile); function pointers use pfn prefix for callbacks (pfnCallback, pfnMessageHandler) or PascalCase for direct calls (ProcessInputEvent, AllocateMemory).

Global variables require g_ prefix: g_dwProcessId, g_abEncryptionKey, g_ServiceStatus (structures), g_szConfigPath (strings), g_adPlayerSlots (arrays), g_pMainWindow (pointers), g_ppModuleList (double pointers). Function pointers use PascalCase without g_. Hungarian prefix MUST match Ghidra type exactly: uint→dw, ushort→w, byte→b/by, char *→lpsz/sz, char * *→pplpsz/ppsz, const char *→lpcsz/csz, void *→p, void * *→pp, byte *→pb, byte * *→ppb, structure *→p+StructName, structure * *→pp+StructName. After renaming, verify type-to-prefix consistency—mismatches indicate incorrect type or prefix.

Replace undefined types before renaming: undefined1→byte, undefined2→ushort/short, undefined4→uint/int/float/pointer, undefined8→double/ulonglong/longlong; undefined1[N]→byte[N], undefined2[N]→ushort[N], undefined4[N]→uint[N]. For pointers, specify complete declaration (float10 * not pointer). Example: UINT type → set to uint → rename with dw prefix (dwFlags or g_dwProcessId); undefined4 flags → set to uint → rename dwMantissaShiftAmount; undefined1[16] XMM storage → set to byte[16] → rename abXmmBuffer.

## Local Variable Renaming

Identify ALL local variables in both decompiled code and disassembly. Use get_function_variables then cross-reference both views. Include everything: parameters (param_1), locals (local_c), SSA temporaries (iVar1, dVar12, dVar21), register inputs (in_ST0, in_XMM0, in_EAX), implicit returns (extraout_EAX), stack parameters (in_stack_00000008), undefined arrays (auVar16[16]), and assembly-only variables (register spills, stack offsets). Never pre-filter by name pattern—attempt renaming ALL variables regardless of perceived difficulty.

**MANDATORY FIRST STEP - Set Data Types:** For EACH variable identified, use set_local_variable_type to set the correct data type BEFORE any renaming. Normalize undefined types (undefined4→int/uint/float/pointer, undefined1→byte, undefined2→ushort/short, undefined8→double/longlong), normalize Windows SDK types (UINT→uint, DWORD→uint, USHORT→ushort, BYTE→byte, BOOL→bool), keep float10 unchanged. Set complete pointer declarations: "uint *" not "pointer", "byte *" not "pointer", "UnitAny *" not "pointer".

**SECOND STEP - Rename Variables:** After ALL variables have correct types set, apply Hungarian notation per type-to-prefix mapping. Build complete rename dictionary for EVERY variable without exclusions. The Hungarian prefix MUST match the Ghidra type you just set in step 1.

For failed renames (verified by count), add PRE_COMMENT with format "VariableName (hungarianName): Description": "in_XMM1_Qa (qwBaseExponent): Quad precision parameter in XMM1", "dVar21 (flTemporaryResult): SSA float temporary", "extraout_XMM0_Oa (ldExtendedValue): Extended precision return in XMM0", "auVar16[16] (abXmmBuffer): XMM register spill". For assembly-only variables, add EOL_COMMENT: "[EBP + -0x14] - dwTempFlags", "XMM2 - flDelta". Document variable re-use patterns at semantic change points.

## Global Data Renaming

Identify and rename ALL global data items: string constants, buffers, configuration values, structure pointers, function pointer tables. Items with DAT_ prefixes or ones that end with the _address or That do not have Hungarian notation prefix or bare addresses must be renamed with Hungarian notation prefixes matching actual data type based on physical size and type in memory. Search disassembly for global references. Use list_data_items_by_xrefs to prioritize high-impact globals, analyze_data_region to determine type and size. Set proper type with apply_data_type before renaming, following type replacement rules. Apply correct prefix using type-to-prefix mapping. Use get_xrefs_to to trace usage across functions. For pointers, use get_xrefs_from to follow pointer chain—set type for and rename both pointer AND data it points to. Use rename_or_label to apply name with correct prefix (works for both defined data and undefined addresses).

**MANDATORY: Rename ALL DAT_* Globals**: Every global referenced by the function with a `DAT_` prefix MUST be renamed using Hungarian notation based on its data type:
- `DAT_6fbf42a0` (dword pointer) → `g_pAutomapConfig`
- `DAT_6fbe9014` (dword flag) → `g_dwSnowModeFlag`
- `DAT_6fbf42cc` (int offset) → `g_nCameraOffsetX`
- `_DAT_*` (underscore prefix) → same rules apply, just rename the core data

Do NOT leave DAT_* globals in the function—they must ALL be renamed before marking complete. Use analyze_data_region to determine type, then rename_or_label to apply the Hungarian-prefixed name.

**String Data Labels (MANDATORY)**: Ghidra auto-detects strings and labels them with `s_` prefix followed by string content and address suffix (e.g., `s_%s\UI\AutoMap\MaxiMap_6fbb2124`). These are string CONTENT used as labels—NOT proper variable names. You MUST rename ALL `s_*` labels to Hungarian notation:
- ANSI strings: `sz` prefix (szAutomapPath, szGameTitle, szErrorMessage)
- Wide strings: `wsz` prefix (wszPlayerName, wszDialogText)
- Format strings: `szFmt` or `szFormat` prefix (szFmtPlayerStats, szFormatPath)
- Path strings: `szPath` prefix (szPathAutomap, szPathResources)

Examples:
- `s_%s\UI\AutoMap\MaxiMap_6fbb2124` → `szAutomapMaxiMapPath`
- `s_Hello_World_6fb12345` → `szHelloWorldMessage`
- `s_%d_%s_6fb98765` → `szFmtIntString`
- `s_C:\Game\Data_6fba0000` → `szPathGameData`

Do NOT leave `s_*` labels unchanged—they violate Hungarian notation and are unreadable.

**Ordinal Function Comments**: When the function calls ordinal imports (Ordinal_XXXXX), add inline comments explaining their purpose. Reference docs/KNOWN_ORDINALS.md for common mappings:
- `Ordinal_10342(pUnit)` → add comment `/* D2Common.GetUnitStat */`
- `Ordinal_10918()` → add comment `/* D2Common.RandSeed - random number generator */`
- `Ordinal_10949(0xffffffff)` → add comment `/* D2Win.GetMapId - get current area ID */`

If an ordinal is not in the reference, analyze its behavior and add a descriptive comment based on context (e.g., `/* Unknown ordinal - appears to validate input */`).

When documenting structure offsets and array strides, clearly distinguish byte offsets, element indices, and calculated addresses. For [EBX + EAX*0x24 + 0x4], break down explicitly: "EBX (base of descriptor table) + EAX*0x24 (index × 36-byte stride) + 0x4 (offset to flags field)". Document stride value, explain what it represents, show how indices are scaled before adding field offsets. For bucket-based indexing (bucket = index >> 5, offset = (index & 0x1F) * stride), document both bucket calculation and within-bucket offset with explicit bit manipulation explanations.

## Cross-Reference Verification for Flags

When documenting flag bits or bit fields, cross-reference all usage sites to verify bit assignments are consistent. Use get_xrefs_to to find all functions accessing the flag, examine how each masks or tests bits (TEST, AND, OR, shifts). If bit 7 is documented as "Binary mode (0x80)" but another function tests it with different meaning, note error or actual flag reuse. Create Flag Usage Cross-Reference subsection in plate comment listing each accessing function and its bit operations.

## Plate Comment Creation

Create comprehensive header with set_plate_comment following docs\prompts\PLATE_COMMENT_FORMAT_GUIDE.md. Use plain text without decorative borders—Ghidra adds formatting. Include: one-line summary; Algorithm section with numbered steps describing operations including validation, function calls, error handling; Parameters section with types (structure types not generic pointers) and purposes, IMPLICIT keyword for undocumented register parameters; Returns section with success values, error codes, NULL/zero conditions; Special Cases for edge cases; Magic Numbers Reference with hex value, decimal, semantic meaning (include whenever function uses numeric constants); Error Handling mapping error paths, API error translations, validation failures, error propagation; State Machine (if complex flow) enumerating execution states and transitions; Structure Layout with ASCII table showing field offsets, sizes, descriptions; Flag Bits with detailed bit table using consistent hex notation.

For flag bits and numeric constants, maintain consistent notation: use hex with 0x prefix (0x02, 0x04, 0x80) not mixed decimal/hex. Align hex values consistently, use same bit numbering (0-7 or 1-8) throughout. If flag is 0x80 in algorithm, use 0x80 in flag table and inline comments—never switch to decimal 128 or binary. Reference ordinals, addresses, magic numbers by values in Algorithm. For structure layouts, use table format with Offset, Size, Field Name, Type, Description columns. Create struct definitions with create_struct. Replace undefined types: undefined1→byte, undefined2→word, undefined4→uint/pointer, undefined8→qword.

**Related Functions Section** (optional but recommended for complex functions): After Magic Numbers Reference, add a Related Functions section listing functions this one calls or is called by, with brief purpose notes:
```
Related Functions:
- InitializeViewportCoordinates() - Must be called first to reset base coords
- RenderAutomapPlayerMarkers() - Called after sprite rendering complete
- GetScrollWindowMode() - Provides panel state input (1=left, 2=right, 3=none)
```
This helps readers understand the function's role in the call graph and required sequencing.

## Algorithm Verification

After creating plate comment with numbered steps, immediately verify each step against decompiled code and assembly for logical correctness. For code like if ((flags & 0x80) == 0) return early, verify whether flag being set or clear triggers early return—documenting backwards misrepresents behavior. Create verification pass confirming each step matches actual code. Pay attention to bitwise operations, conditional logic, early returns where semantic meaning can invert. Create explicit algorithm-to-code mapping connecting numbered steps to specific lines/addresses implementing them. Include as inline comments: "Algorithm Step 3: Check buffer exhausted and refill". This bidirectional mapping ensures readers trace from description to implementation and forces verification that every step has code and every code block has step. If code doesn't map to any step, add step or determine it's edge case for Special Cases section.

## Inline Comments

Add comprehensive decompiler comments with batch_set_comments. Decompiler comments (PRE_COMMENT) appear above code line explaining context, purpose, structure access, magic numbers, validation logic, edge cases, variable re-use, algorithm step references. For complex control flow with multiple branches or state transitions, create state machine section in plate comment enumerating execution states and transitions: "State 1: CR followed by LF → Output LF, advance by 2", "State 2: CR at buffer end → Read ahead for LF, buffer CR if no LF". This transforms opaque logic into decision tree.

Disassembly comments (EOL_COMMENT) appear at assembly line end without disrupting flow. Do NOT use PRE_COMMENT for disassembly—end-of-line strongly preferred to maintain visual flow. Pre-comments create clutter and break top-to-bottom reading pattern. Disassembly comments should be concise (max 32 characters): "Load player slot index", "Check if slot active", "Jump to error handler". Verify offset values against actual assembly before adding—assembly shows true offsets where [EBX + 0x4] means offset +4 from base. Match comment offsets to disassembly not decompiler line order. Document memory access patterns not just variable loads.

## Verification and Completeness

**CRITICAL**: Before marking any function complete, you MUST achieve 100% completeness score. Use analyze_function_completeness() and iteratively fix all reported issues until the score reaches 100.

**Completion Workflow:**

1. **Manual Plate Comment Verification** (REQUIRED before using completeness tool):
   - Read the decompiled code output with get_decompiled_code() or decompile_function()
   - Manually verify the plate comment contains ALL required sections:
     - One-line summary at the top
     - "Algorithm:" header with blank line before it and numbered steps
     - "Parameters:" section documenting all parameters (including IMPLICIT register params)
     - "Returns:" section explaining return values and conditions
     - "Special Cases:" section for edge cases and magic numbers (if applicable)
     - "Structure Layout:" tables if function accesses structures (if applicable)
   - The completeness tool only checks IF a plate comment exists, NOT whether it follows the format guide
   - You MUST manually verify format before proceeding

2. **Run analyze_function_completeness(function_address)**:
   - Review completeness_score (0-100)
   - Examine all issue arrays: plate_comment_issues, hungarian_notation_violations, undefined_variables, type_quality_issues, undefined_type_globals, unnamed_globals
   - The tool validates all documentation requirements automatically

3. **Fix All Reported Issues**:
   - Address every item in the issue arrays
   - Use appropriate tools: set_plate_comment, rename_variables, set_local_variable_type, set_function_prototype, rename_or_label
   - Do NOT skip or ignore ANY reported issues

4. **Re-run analyze_function_completeness() After Each Fix**:
   - Verify the issue was resolved
   - Check if completeness_score increased
   - Continue iterating until score reaches 100

5. **If Score Does Not Reach 100 After 3 Attempts**:
   - Try different approaches:
     - Attempt 1: Fix issues in the order reported by the tool
     - Attempt 2: Focus on highest-impact issues first (type_quality_issues, plate_comment_issues)
     - Attempt 3: Manually verify decompiled output, check for stale cached data, force decompilation with force=true
   - Document why 100% cannot be achieved (e.g., tool caching bugs, non-renameable SSA variables)
   - Only move to next function after 3 genuine attempts with different strategies

6. **Orphaned Function Detection** (After reaching 100% or exhausting attempts):
   - Check for orphaned functions after current function
   - Examine disassembly at function end for unconditional RET
   - Look for executable code after RET with no conditional jumps targeting it
   - Use get_xrefs_to to check if orphaned addresses referenced from data (function pointer tables)
   - If found, use create_function and add to documentation queue

**Minimum Standard: 100% completeness_score required before moving to next function.**

**Exception**: Only move on with less than 100% after 3 documented fix attempts using different strategies, with clear explanation of blockers.

## Output Format

When documentation is complete, output EXACTLY this 3-line format (no markdown, no extra text):
```
DONE: FunctionName
Score: XX%
Changes: [brief summary of changes made]
```

Example:
```
DONE: UpdateAutomapRenderingAndCamera
Score: 100%
Changes: Renamed function, set prototype, typed/renamed 12 variables, renamed 8 globals, added plate comment with 18-step algorithm, 32 inline comments
```