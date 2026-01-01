# Documentation Workflow Reference Index

A quick reference for which tools and documents to use at each stage of the Ghidra binary function documentation process.

## Quick Navigation

- **Starting a new function?** → Read [OPTIMIZED_FUNCTION_DOCUMENTATION.md](OPTIMIZED_FUNCTION_DOCUMENTATION copy.md)
- **Naming conventions?** → See [NAMING_CONVENTIONS.md](../../NAMING_CONVENTIONS.md)
- **Missed a global?** → Use [GLOBAL_DATA_NAMING_CHECKLIST.md](GLOBAL_DATA_NAMING_CHECKLIST.md)
- **Tool reference?** → Check [MCP_TOOLS_QUICK_REFERENCE.md](#mcp-tools-quick-reference) below

---

## Workflow Decision Tree

```text
START: New function to document
  │
  ├─→ Have decompilation & disassembly?
  │   NO → Run: batch_decompile_functions, disassemble_function
  │   YES → Continue
  │
  ├─→ Rename function with correct naming convention?
  │   Use: rename_function_by_address
  │   Naming: PascalCase (e.g., InitializeCommandLineSettings)
  │
  ├─→ Set function prototype with calling convention?
  │   Use: set_function_prototype
  │   Conventions: __cdecl, __stdcall, __fastcall, __thiscall
  │
  ├─→ Create labels for all jump targets?
  │   Use: batch_create_labels (recommended)
  │   Naming: snake_case (e.g., check_if_state_is_menu)
  │   Max batch size: 20 items (use multiple calls if >20)
  │
  ├─→ Rename ALL global data referenced (STRING CONSTANTS, BUFFERS)?
  │   Use: GLOBAL_DATA_NAMING_CHECKLIST.md
  │   CRITICAL: Search for all DAT_ and string address references
  │   Tools: inspect_memory_content (verify strings), rename_or_label
  │
  ├─→ Rename function-local variables?
  │   Use: rename_variable (one at a time) or batch_rename_function_components
  │   Naming: camelCase (e.g., configBuffer, registryValue)
  │   Note: Does NOT work on globals - use rename_or_label instead
  │
  ├─→ Add decompiler comments?
  │   Use: batch_set_comments (multiple) or set_decompiler_comment (one)
  │   Focus: Explain algorithm, data flow, key decisions
  │
  ├─→ Add disassembly comments?
  │   Use: set_disassembly_comment (one at a time)
  │   Focus: Explain register usage, memory access, calling conventions
  │
  ├─→ Add function header (plate) comment?
  │   Use: set_plate_comment
  │   Content: Algorithm overview, parameters, return value, key operations
  │
  └─→ Verification: All items renamed?
      Checklist:
      ├─ [ ] No DAT_ prefixes in decompilation
      ├─ [ ] No bare numeric addresses in decompilation
      ├─ [ ] All strings have sz prefix
      ├─ [ ] All variables camelCase
      ├─ [ ] All labels snake_case
      ├─ [ ] Comments explain purpose of each code block
      └─→ COMPLETE ✓
```

---

## MCP Tools Quick Reference

### Function Analysis (Read-Only)

| Tool | Purpose | Example |
|------|---------|---------|
| `batch_decompile_functions` | Decompile up to 20 functions | `batch_decompile_functions(["function1", "function2"])` |
| `decompile_function` | Decompile single function | `decompile_function(name="main")` |
| `disassemble_function` | Get assembly with operands | `disassemble_function(address="0x401000")` |
| `get_function_variables` | List parameters and locals | `get_function_variables("main")` |
| `get_function_callees` | Functions called by target | `get_function_callees("main")` |
| `get_function_callers` | Functions calling target | `get_function_callers("main")` |
| `get_function_jump_target_addresses` | All JMP/JE/JNE targets | `get_function_jump_target_addresses("main")` |
| `get_function_labels` | Labels within function | `get_function_labels("main")` |
| `get_xrefs_to` | Who references this address | `get_xrefs_to(address="0x401000")` |
| `inspect_memory_content` | Read memory as hex/ASCII | `inspect_memory_content(address="0x0040a488", length=16, detect_strings=true)` |

### Renaming Operations

| Tool | Purpose | Use Case |
|------|---------|----------|
| `rename_function_by_address` | Rename function | At start of documentation |
| `rename_variable` | Rename function-local variable | After renaming function |
| `rename_or_label` | Rename data or create label | For globals and strings (MUST use for DAT_ items) |
| `batch_rename_function_components` | Rename function + params + locals atomically | When doing complete rename operation |

### Typing & Structure

| Tool | Purpose | Use Case |
|------|---------|----------|
| `set_function_prototype` | Set signature + calling convention | After function rename |
| `set_local_variable_type` | Change parameter/local type | When variable analysis shows wrong type |
| `create_struct` | Define new structure type | When discovering data structure |
| `apply_data_type` | Apply type to memory address | When defining global data |

### Labeling & Navigation

| Tool | Purpose | Use Case |
|------|---------|----------|
| `create_label` | Create single label | For special landmarks |
| `batch_create_labels` | Create multiple labels (max 50) | After identifying jump targets |
| `rename_label` | Rename existing label | If initial label name incorrect |

### Documentation (Comments)

| Tool | Purpose | Max Batch Size |
|------|---------|----------------|
| `set_plate_comment` | Function header comment | N/A (single operation) |
| `set_decompiler_comment` | Comment in pseudocode | N/A (single operation) |
| `set_disassembly_comment` | Comment in assembly | N/A (single operation) |
| `batch_set_comments` | Multiple comments atomically | 20-25 per batch |

### Batch Operation Limits

⚠️ **IMPORTANT**: Large batches cause timeouts. Use smaller batches when possible:

- **Labels**: Max 20-30 per batch (tested: 44 succeeded with 7 pre-existing)
- **Comments**: Max 20-25 per batch (tested: 125 spread across 3 batches)
- **General**: When in doubt, use batch size of 10-15 items

---

## Naming Convention Quick Reference

### Functions

```text
Pattern: PascalCase (Action+Target)
Examples:
  ✓ InitializeCommandLineSettings
  ✓ RunGameMainLoop
  ✓ ProcessPlayerSkillCooldowns
  ✗ initialize_command_line (too verbose, snake_case)
  ✗ InitCmdLine (too abbreviated)
```

### Variables (Local)

```text
Pattern: camelCase (type+purpose)
Examples:
  ✓ configBuffer
  ✓ registryValue
  ✓ playerCount
  ✗ config_buffer (snake_case)
  ✗ CONFIGBUFFER (UPPER_CASE)
```

### Global Data

```text
Pattern: Semantic name (no DAT_ prefix)
Examples:
  ✓ cmdlineSharedBuffer
  ✓ gameStateTable
  ✓ configSettings
  ✗ DAT_0040ce18 (original default)
  ✗ gameState_0x0040cf30 (mixed naming)
```

### String Constants

```text
Pattern: sz prefix (Hungarian notation)
Examples:
  ✓ szCmdLineRegValue ("CmdLine")
  ✓ szGameRegKeyName ("Diablo II")
  ✓ szCmdLineFormatString ("%s -skiptobnet")
  ✗ s_CmdLine_0040a488 (old naming, numeric suffix)
  ✗ cmdlineValue (missing sz prefix)
```

### Labels (Jump Targets)

```text
Pattern: snake_case (description)
Examples:
  ✓ check_if_state_is_menu
  ✓ registry_query_failed
  ✓ initialize_next_subsystem
  ✗ CheckIfStateIsMenu (PascalCase)
  ✗ STATE_MENU_CHECK (ALL_CAPS)
```

### Structure Pointers

```text
Pattern: p/ptr prefix (Hungarian notation)
Examples:
  ✓ pGameState
  ✓ pPlayerData
  ✓ pEntityList
  ✗ gameState (unclear it's a pointer)
  ✗ gameStatePtr (mixing patterns)
```

---

## Common Patterns by Function Type

### Initialization Functions

**Pattern**: Setup resources → Configure from registry/parameters → Validate → Return status

**Global Data to Expect**:

- Registry key names (sz prefix)
- Registry value names (sz prefix)
- Configuration buffers
- Flag variables (init complete, success status)

**Naming Examples**:

- `InitializeCommandLineSettings`
- `InitializeGraphicsSubsystem`
- `LoadConfigurationFromRegistry`

### State Machine Functions

**Pattern**: Loop on state → Dispatch to handler → Invoke next state → Cleanup

**Global Data to Expect**:

- State variable (current state)
- Handler table (function pointers)
- State constants (state 0=exit, state 2=menu)

**Naming Examples**:

- `RunGameMainLoop`
- `DispatchGameState`
- `ProcessGameStateTransition`

### Service Functions

**Pattern**: Entry point → Initialize → Main loop → Cleanup → Report status

**Global Data to Expect**:

- Service status structure
- Service running flag
- Service handle

**Naming Examples**:

- `ServiceMainD2Server`
- `ServiceControlHandler`
- `ReportServiceStatus`

---

## Troubleshooting Common Issues

### Issue: "DAT_" prefix remains after trying to rename

**Cause**: Using `rename_variable` instead of `rename_or_label`

**Solution**: Use `rename_or_label(address, newName)` for global data

```text
❌ rename_variable("function_name", "DAT_0040ce18", "newName")
✅ rename_or_label("0x0040ce18", "newName")
```

### Issue: String constants still show as bare addresses

**Cause**: Not systematically searching for string references

**Solution**: Use GLOBAL_DATA_NAMING_CHECKLIST.md to find all strings

```text
Before (missing):
  MOV EDX, [0x0040a488]  ; Bare address!

After (complete):
  MOV EDX, [szCmdLineRegValue]  ; Named!
```

### Issue: Batch operation times out

**Cause**: Batch size too large (>30 items)

**Solution**: Split into smaller batches

```text
❌ 50 labels in one batch_create_labels call
✅ 20 + 20 + 10 in three separate calls
```

### Issue: Cannot rename already-existing label

**Cause**: Usually means previous rename succeeded but tool reported error

**Solution**: Check if rename actually succeeded before retrying

```text
Response: "Duplicate name... already exists"
→ This usually means the rename already happened!
→ Verify by checking decompilation or running get_function_labels
```

---

## Document Cross-Reference

| Task | Document |
|------|----------|
| Complete 12-step function documentation | [OPTIMIZED_FUNCTION_DOCUMENTATION.md](OPTIMIZED_FUNCTION_DOCUMENTATION copy.md) |
| All naming conventions | [NAMING_CONVENTIONS.md](../../NAMING_CONVENTIONS.md) |
| Global data and string renaming | [GLOBAL_DATA_NAMING_CHECKLIST.md](GLOBAL_DATA_NAMING_CHECKLIST.md) |
| MCP tool examples and parameters | [MCP_TOOLS_REFERENCE.md](../mcp_tools/README.md) |
| Version management | [VERSION_MANAGEMENT_STRATEGY.md](../../VERSION_MANAGEMENT_STRATEGY.md) |
| Maven build configuration | pom.xml (version source of truth) |

---

## Next Steps After Reading This Reference

1. **Choose your next function** → Get its address via `get_current_selection()`
2. **Follow the Decision Tree** above (top to bottom)
3. **Use GLOBAL_DATA_NAMING_CHECKLIST.md** when you reach the globals step
4. **Reference the Naming Conventions** for each symbol type
5. **Check Tool Limits** before running batch operations
6. **Verify Completion** against the checklist at bottom of decision tree

