# Plate Comment Examples

This document provides complete, real-world examples of properly formatted plate comments for different function types.

**CRITICAL**: Use plain text with NO decorative borders - Ghidra adds all formatting automatically!

## Example 1: Validation Function

```
Validates whether armor equipment can be equipped by a player.

Algorithm:
1. Check if item pointer is not NULL
2. Call Ordinal_10444 to validate item structure
3. Check if player entity can receive items
4. Verify unit type is player (type == 1)
5. Get armor class from player's skill
6. Validate armor class against game data limits
7. Special handling for armor class 0x4e (78)

Parameters:
  param_1: Unknown parameter (not used in function body)
  itemPointer: Pointer to item structure being validated
  playerUnit: Player unit pointer (passed via ESI register)

Returns:
  BOOL: TRUE (1) if armor can be equipped, FALSE (0) otherwise

Special Cases:
  - Armor class 0x4e requires special validation
  - Returns false if armor class exceeds game data limit at offset +0xa80
```

## Example 2: Data Processing Function with Structure

```
Processes timed spell effects for all active players in the game.

Algorithm:
1. Load base address of FrameThresholdDataTable (0x6fb835b8)
2. Iterate through all player slots (0 to MAX_PLAYERS)
3. For each slot, check if player unit is active
4. Get current game frame count from global state
5. Compare against threshold value in data table
6. If threshold exceeded, trigger spell effect processing
7. Update timestamp for next trigger calculation
8. Skip to next player on validation failure

Parameters:
  None (operates on global game state)

Returns:
  void

Structure: FrameThresholdDataTable (0x6fb835b8)
  Offset  | Size | Field Name       | Type    | Description
  --------|------|------------------|---------|------------------------------------------
  +0x00   | 4    | dwThreshold      | DWORD   | Frame count threshold for effect trigger
  +0x04   | 4    | dwEffectId       | DWORD   | Spell effect identifier
  +0x08   | 4    | dwDuration       | DWORD   | Effect duration in frames
  +0x0c   | 4    | dwFlags          | DWORD   | Processing flags and state
  Total Size: 16 bytes per entry, 4 entries = 64 bytes

Special Cases:
  - Inactive player slots are skipped without processing
  - Threshold value 0xFFFFFFFF disables effect for that slot
```

## Example 3: Initialization Function

```
Initializes game resource system and loads configuration data.

Algorithm:
1. Allocate memory for resource manager structure (512 bytes)
2. Initialize all pointer fields to NULL
3. Load resource configuration from game data file
4. Validate configuration CRC checksum
5. Parse resource type table and build lookup index
6. Register resource cleanup handlers with exit manager
7. Set global resource manager pointer
8. Return initialization status code

Parameters:
  configPath: Pointer to null-terminated path string for config file
  allocFlags: Memory allocation flags (0x01 = zero-fill, 0x02 = protected)

Returns:
  int: 0 on success, negative error code on failure
       -1 = memory allocation failed
       -2 = config file not found
       -3 = invalid checksum

Special Cases:
  - If config file missing, uses hardcoded defaults from 0x6fba9e00
  - Cleanup handlers only registered if allocation succeeds
  - Global pointer remains NULL if initialization fails
```

## Example 4: String Processing Function

```
Converts locale-specific string using character mapping table.

Algorithm:
1. Validate input string pointer is not NULL
2. Get string length using strlen
3. Allocate output buffer (length + 1 for null terminator)
4. Load SehFrameLocaleMapping table pointer (0x6fb7f528)
5. For each character in input string:
   a. Get character code as unsigned byte
   b. Look up replacement in mapping table
   c. If mapping exists, use mapped character
   d. Otherwise, copy original character
6. Append null terminator to output buffer
7. Return pointer to converted string

Parameters:
  inputString: Pointer to source null-terminated string
  localeId: Locale identifier (0=English, 1=French, 2=German, 3=Spanish)

Returns:
  char*: Pointer to newly allocated converted string, or NULL on error

Special Cases:
  - Returns NULL if input string is NULL
  - Returns NULL if memory allocation fails
  - Unmapped characters are copied verbatim (no conversion)
  - Caller is responsible for freeing returned string
```

## Example 5: Array/Table Processing

```
Searches MonthNameTable for matching month string and returns index.

Algorithm:
1. Load base address of MonthNameTable (0x6fb7ff00)
2. Initialize loop counter to 0
3. For each entry in table (max 12 entries):
   a. Load string pointer from table at [base + counter*4]
   b. Compare with search string using strcmp
   c. If match found, return current counter value
   d. Increment counter and continue
4. If loop completes without match, return -1

Parameters:
  searchString: Pointer to null-terminated month name to find

Returns:
  int: Month index (0-11) if found, -1 if not found

Structure: MonthNameTable (0x6fb7ff00)
  Array of 12 DWORD pointers to month name strings
  Offset  | Value
  --------|--------------------------------------------------------------------
  +0x00   | Pointer to "January" string
  +0x04   | Pointer to "February" string
  +0x08   | Pointer to "March" string
  ...     | (continues for all 12 months)
  +0x2c   | Pointer to "December" string
  Total Size: 48 bytes (12 entries * 4 bytes per pointer)

Special Cases:
  - Search is case-sensitive
  - Returns -1 for NULL or empty search string
```

## Example 6: Minimal Function (Simple Getter)

```
Returns the current player's skill level for specified skill ID.

Algorithm:
1. Get player unit pointer from global state
2. Validate player unit is not NULL
3. Access skill array at player+0x5c
4. Index into array using skillId parameter
5. Return skill level value as BYTE

Parameters:
  skillId: Skill identifier (0-255)

Returns:
  BYTE: Skill level (0-99), or 0 if player is NULL or skillId invalid
```

## Formatting Checklist

When creating a plate comment, verify:

- [ ] NO decorative borders or asterisks - Ghidra adds these
- [ ] NO comment markers `/*` or `*/` - Ghidra adds these
- [ ] Plain text only with clean formatting
- [ ] Function summary is one clear sentence
- [ ] Algorithm section has numbered steps
- [ ] All parameters are documented with types and purposes
- [ ] Return values and conditions are explained
- [ ] Special cases section included if there are edge cases
- [ ] Structure layout included if function accesses structs
- [ ] Use 2-space indentation for nested items
- [ ] Magic numbers are explained with hex and decimal values
- [ ] Referenced addresses and ordinals are included

## Quick Template Generator

For quick prototyping, use this minimal template and expand:

```
[FUNCTION PURPOSE IN ONE SENTENCE]

Algorithm:
1. [STEP 1]
2. [STEP 2]
3. [STEP 3]

Parameters:
  param1: [TYPE AND PURPOSE]

Returns:
  [TYPE]: [WHAT IT MEANS]
```

Remember: Provide plain text only - Ghidra handles all comment formatting automatically.
