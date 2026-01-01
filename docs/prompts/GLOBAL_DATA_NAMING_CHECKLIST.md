# Global Data Naming Checklist

This checklist ensures that **all global data items** are properly renamed with appropriate naming conventions, preventing the miss of string constants and shared buffers that occurred in previous documentation efforts.

## Pre-Documentation Phase

Before starting function documentation, **scan the entire function disassembly for all global data references**:

- [ ] Review disassembly for all memory addresses (e.g., `[0x0040a488]`, `DAT_0040ce18`)
- [ ] Identify all string literal addresses in instruction operands
- [ ] Identify all configuration/state variable addresses
- [ ] Identify all buffer/table addresses
- [ ] Create a list of all unique global addresses found

## String Constants - CRITICAL PRIORITY

**String constants MUST be renamed with `sz` prefix.** These are often missed because they appear as bare addresses in disassembly.

### Search Strategy

For each string address found:

1. [ ] Verify it's actually a string by reading memory with `inspect_memory_content`
2. [ ] Extract the string value (e.g., "CmdLine", "Diablo II", "SkipToBnet")
3. [ ] Create descriptive name with `sz` prefix:
   - Registry keys: `szGameRegKeyName`, `szRegistryKeyPath`
   - Registry values: `szCmdLineRegValue`, `szFixedAspectRatioValue`, `szResolutionRegValue`
   - Format strings: `szCmdLineFormatString`, `szErrorMessageFormat`
   - Default strings: `szCmdLineSkipToBnet`, `szDefaultConfigValue`
   - Error messages: `szErrorMessage`, `szWarningMessage`
4. [ ] Rename using `rename_or_label(address, szDescriptiveName)`

### Common Patterns to Watch For

- Registry key names (e.g., "Diablo II", "HKEY_LOCAL_MACHINE")
- Registry value names (e.g., "CmdLine", "UseCmdLine", "SvcCmdLine")
- Format strings (e.g., "%s -skiptobnet", "%d bytes")
- Command line flags (e.g., "-skiptobnet", "-log")
- Default configuration strings
- Error message strings

## Global Buffers & Arrays

**Buffers and arrays should use descriptive names without DAT_ prefix.**

For each buffer/array found:

1. [ ] Determine the buffer's purpose by tracing usage across all referencing functions
2. [ ] Calculate or verify buffer size (look for allocation patterns, loop bounds, comparisons)
3. [ ] Assign descriptive name:
   - Command line buffers: `cmdlineSharedBuffer`, `cmdlineRegistry`, `cmdlineService`
   - Configuration tables: `configTable`, `settingsBuffer`, `optionsList`
   - Player/entity data: `playerSlotArray`, `entityList`, `unitArray`
   - Lookup tables: `functionPointerArray`, `stateHandlerTable`, `messageTable`
   - Temporary buffers: `tempBuffer`, `scratchMemory`, `workBuffer`
4. [ ] Rename using `rename_or_label(address, descriptiveName)`

## Global Flags & Single Values

**Single configuration/state values should use descriptive names.**

For each flag/value found:

1. [ ] Determine if it's a flag (boolean, set to 0/1) or configuration value
2. [ ] Trace all assignments to understand its semantic meaning
3. [ ] Assign descriptive name:
   - Service flags: `isServiceRunning`, `serviceInitFlag`, `serviceShutdownRequested`
   - Game state: `currentGameState`, `gameLoopActive`, `pausedFlag`
   - Feature flags: `soundEnabled`, `graphicsInitialized`, `keyhookEnabled`
   - Configuration: `maxPlayerCount`, `gameVersion`, `debugLevel`
   - Handles/references: `serviceHandle`, `keyhookLibHandle`, `cleanupCallback`
4. [ ] Rename using `rename_or_label(address, descriptiveName)`

## Structure Pointers

**Structure pointers should use descriptive names indicating the data type.**

For each structure pointer found:

1. [ ] Determine what structure is pointed to
2. [ ] Assign name with `p` or `ptr` prefix:
   - Game state: `pGameState`, `pGameConfig`, `gameStatePtr`
   - Player data: `pPlayerData`, `playerArrayPtr`
   - System config: `pSystemConfig`, `configStructPtr`
   - Level/room: `pCurrentLevel`, `pGameLevel`
   - Entity: `pEntityList`, `unitArrayPtr`
3. [ ] Rename using `rename_or_label(address, descriptiveName)`

## Function Pointers & Callbacks

**Function pointers and callback references should indicate their purpose.**

For each function pointer found:

1. [ ] Determine what function(s) it points to
2. [ ] Assign descriptive name:
   - Service handlers: `serviceControlHandler`, `shutdownCallback`, `cleanupRoutine`
   - State handlers: `stateHandlerTable`, `commandDispatcher`
   - Event callbacks: `keyboardHookCallback`, `timerCallback`
3. [ ] Rename using `rename_or_label(address, descriptiveName)`

## Post-Documentation Verification

After documenting a function, verify all globals were renamed:

- [ ] Search for all remaining `DAT_` prefixes in the function decompilation
- [ ] Search for all bare numeric addresses (e.g., `0x0040a488`) in decompilation
- [ ] Search for all bare numeric addresses in disassembly comments
- [ ] Verify all string literal addresses in disassembly have been renamed with `sz` prefix
- [ ] If any remain, add them to the global data renaming section and complete before marking function as done

## Testing & Validation

For each renamed global:

- [ ] Verify the name appears in all referencing functions' decompilation
- [ ] Confirm the name matches the data type (e.g., `sz` for strings, `p` for pointers)
- [ ] Check that the name is descriptive enough to understand purpose without context
- [ ] Ensure no DAT_ prefixes or bare addresses remain in decompilation

## Common Mistakes to Avoid

❌ **WRONG**: Leaving string constants as `s_CmdLine_0040a488`  
✅ **RIGHT**: Rename to `szCmdLineRegValue`

❌ **WRONG**: Leaving buffers as `DAT_0040ce18`  
✅ **RIGHT**: Rename to `cmdlineSharedBuffer`

❌ **WRONG**: Using inconsistent prefixes (e.g., `str_` instead of `sz` for strings)  
✅ **RIGHT**: All null-terminated strings use `sz` prefix

❌ **WRONG**: Not renaming registry value names referenced in assembly  
✅ **RIGHT**: All registry keys and values renamed with `sz` prefix

❌ **WRONG**: Stopping at function-local variables without renaming globals  
✅ **RIGHT**: Complete global data renaming before marking function complete

## Integration with Documentation Workflow

This checklist should be performed **during the variable renaming phase** of the main documentation workflow, but with **extended scope beyond function-local variables**:

1. During analysis, note ALL global data referenced
2. Rename function variables first (existing workflow)
3. **BEFORE adding comments, complete global data renaming** (this checklist)
4. Continue with plate comment and inline comments
5. Final verification includes confirming all globals are renamed
