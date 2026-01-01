# Function Documentation Completeness Checklist

Use this checklist when documenting functions to ensure nothing is missed.

## Pre-Documentation

- [ ] **Verify function boundaries**: Confirm the function starts and ends at correct addresses
- [ ] **Check if function can be decompiled**: If not, document based on disassembly analysis
- [ ] **Identify all callers**: Use `get_function_callers()` to understand context
- [ ] **Identify all callees**: Use `get_function_callees()` to understand dependencies

## Function-Level Documentation

- [ ] **Rename function**: Use descriptive name based on purpose (no `FUN_` prefix)
- [ ] **Set function prototype**: Include return type, parameter types, and calling convention
- [ ] **Add plate comment**: Comprehensive header comment explaining:
  - Purpose and algorithm
  - Parameter descriptions
  - Return value description
  - Special cases and error conditions
  - Related functions or context

## Variable Documentation

- [ ] **Rename all parameters**: Use descriptive names (no `param_1`, `param_2`, etc.)
- [ ] **Rename all local variables**: Use descriptive names (no `local_8`, `iVar1`, `uVar2`, etc.)
- [ ] **Set variable types**: Apply correct data types for all variables
- [ ] **Verify structure pointers**: If parameters are pointers to structures, set the structure type

## Global Data Documentation

### Critical Step - Often Missed!

- [ ] **Extract ALL global references from decompiled code**: Look for `DAT_` prefixes
- [ ] **Extract ALL global references from disassembly**: Use `get_disassembly()` and look for memory addresses in brackets `[0x...]`
- [ ] **Check nearby code for orphaned globals**: Sometimes references appear between functions
  - List all globals in the memory range: `list_globals(filter="<address_prefix>")`
  - Check xrefs for each global: `get_xrefs_to(address)`
  - If the global is referenced by related functions, document it now

- [ ] **For EACH global reference found**:
  - [ ] Rename with proper Hungarian notation prefix:
    - `g_dw` = global DWORD (4 bytes)
    - `g_w` = global WORD (2 bytes)
    - `g_b` = global BYTE (1 byte)
    - `g_sz` = global null-terminated string
    - `g_p` = global pointer
    - `g_pp` = global pointer to pointer
    - `g_n` = global count/number
    - `g_h` = global handle
    - `g_f` = global flag/boolean
  - [ ] Set proper data type (not `undefined4`, use `dword`, `pointer`, `char[N]`, etc.)
  - [ ] Add comment explaining the global's purpose

### Example Global Naming

```
DAT_6ffa8260 (4 bytes, used as count)     → g_nFileStreamCount (type: dword)
DAT_6ffa7240 (4 bytes, array pointer)     → g_ppFileStreamTable (type: pointer)
DAT_6ff7514c (4 bytes, function pointer)  → g_pfnAllocateMemory (type: pointer)
DAT_6fba9dec (null-term string)           → g_szErrorMessage (type: char[64])
```

## Code Comments

- [ ] **Add decompiler comments**: Use `set_decompiler_comment()` for complex logic blocks
- [ ] **Add disassembly comments**: Use `set_disassembly_comment()` for assembly-specific details
- [ ] **Create labels**: Use `batch_create_labels()` for jump targets and code sections

## Verification

- [ ] **Force refresh decompilation**: After structural changes, use `refresh_cache=True`
  ```python
  get_decompiled_code(address, refresh_cache=True)
  ```
- [ ] **Review decompiled code**: Ensure all names make sense and no `DAT_`, `param_`, `local_` remain
- [ ] **Run verification script**:
  ```bash
  python verify_function_documentation.py <address>
  ```
- [ ] **Check for undefined types**: All globals should have concrete types, not `undefined4`

## Common Mistakes to Avoid

1. ❌ **Only checking decompiled code for globals**: Globals may appear in disassembly but not decompiled code
2. ❌ **Ignoring globals referenced nearby**: Check memory ranges around the function
3. ❌ **Leaving types as undefined**: Always set proper data types (dword, pointer, char[], etc.)
4. ❌ **Not using refresh_cache**: After renaming globals/variables, force re-decompilation to verify
5. ❌ **Generic variable names**: Names should describe PURPOSE, not just type (e.g., `streamCount` not `dwCount`)

## Automation Tools

### Quick Global Discovery Pattern

When documenting a function at address `0x6ff56788`:

```python
# 1. Get the function
func_info = get_function_by_address("0x6ff56788")

# 2. Check disassembly for memory references
disasm = get_disassembly("0x6ff56788")
# Look for patterns like: MOV EAX,[0x6ffa8260]

# 3. List all globals in that memory range
globals_list = list_globals(filter="6ffa")  # Use address prefix

# 4. For each global found, check its xrefs
xrefs = get_xrefs_to("0x6ffa8260")

# 5. If related to current function's purpose, rename it
rename_or_label("0x6ffa8260", "g_nFileStreamCount")

# 6. Force refresh to see changes
get_decompiled_code("0x6ff56788", refresh_cache=True)
```

### Batch Global Renaming

For functions with many globals (10+), use a batch approach:

```python
# Define all renames
global_renames = {
    "0x6ffa8260": "g_nFileStreamCount",
    "0x6ffa7240": "g_ppFileStreamTable",
    "0x6ff7514c": "g_pfnAllocateMemory"
}

# Apply all renames
for addr, name in global_renames.items():
    rename_or_label(addr, name)

# Force refresh decompilation
get_decompiled_code(function_address, refresh_cache=True)
```

## Final Sign-Off

Before moving to the next function:

- [ ] **No `DAT_` prefixes remain** in decompiled code or nearby memory
- [ ] **No `param_X` or `local_X` names** in variable list
- [ ] **All types are concrete** (no `undefined4`, `undefined1`, etc.)
- [ ] **Plate comment is comprehensive** (explains purpose, algorithm, parameters, return)
- [ ] **Function name is descriptive** (explains what it does, not how)
- [ ] **Verification script passes**: Returns "DOCUMENTATION COMPLETE"

---

**Remember**: The goal is to make the decompiled code readable by someone who has never seen this binary before. Every `DAT_`, `param_`, and `undefined` makes that harder. Document thoroughly!
