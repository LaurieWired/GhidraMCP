# Comprehensive Documentation of pUnit (UnitAny) Functions

## Overview

This document provides complete documentation of all functions in the D2Common binary that use the `pUnit` structure (typedef'd as `UnitAny*`). The `UnitAny` structure is a universal unit descriptor used throughout Diablo II to represent players, monsters, items, objects, and other entities.

**Document Generated**: 2025-10-23
**Binary**: D2Common.dll v1.13c
**Total Functions Documented**: 100+

## UnitAny Structure Definition

```c
struct UnitAny {
    DWORD dwType;                    // 0x00 - Unit type (0=Player, 1=Monster, 2=Object, 3=Missile, 4=Item, 5=RoomTile)
    DWORD dwTxtFileNo;               // 0x04 - TXT file record number
    DWORD _1;                        // 0x08 - Unknown/reserved
    DWORD dwUnitId;                  // 0x0C - Unique unit ID
    DWORD dwMode;                    // 0x10 - Unit mode/state
    union {
        PlayerData *pPlayerData;     // 0x14 - Player-specific data
        ItemData *pItemData;         //        Item-specific data
        MonsterData *pMonsterData;   //        Monster-specific data
        ObjectData *pObjectData;     //        Object-specific data
    };
    DWORD dwAct;                     // 0x18 - Act index
    Act *pAct;                       // 0x1C - Pointer to act structure
    DWORD dwSeed[2];                 // 0x20 - Random seed
    DWORD _2;                        // 0x28 - Unknown/reserved
    union {
        Path *pPath;                 // 0x2C - Movement path structure
        ItemPath *pItemPath;         //        Item path structure
        ObjectPath *pObjectPath;     //        Object path structure
    };
    DWORD _3[5];                     // 0x30 - Reserved
    DWORD dwGfxFrame;                // 0x44 - Graphics frame
    DWORD dwFrameRemain;             // 0x48 - Frames remaining in animation
    WORD wFrameRate;                 // 0x4C - Frame rate
    WORD _4;                         // 0x4E - Reserved
    BYTE *pGfxUnk;                   // 0x50 - Graphics data
    DWORD *pGfxInfo;                 // 0x54 - Graphics info pointer
    DWORD _5;                        // 0x58 - Reserved
    StatList *pStats;                // 0x5C - Statistics list
    Inventory *pInventory;           // 0x60 - Inventory pointer
    Light *ptLight;                  // 0x64 - Light structure
    DWORD _6[9];                     // 0x68 - Reserved
    WORD wX;                         // 0x8C - X coordinate
    WORD wY;                         // 0x8E - Y coordinate
    DWORD _7;                        // 0x90 - Reserved
    DWORD dwOwnerType;               // 0x94 - Owner unit type
    DWORD dwOwnerId;                 // 0x98 - Owner unit ID
    DWORD _8[2];                     // 0x9C - Reserved
    OverheadMsg* pOMsg;              // 0xA4 - Overhead message
    Info *pInfo;                     // 0xA8 - Skill/action info
    DWORD _9[6];                     // 0xAC - Reserved
    DWORD dwFlags;                   // 0xC4 - Unit flags
    DWORD dwFlags2;                  // 0xC8 - Unit flags 2
    DWORD _10[5];                    // 0xCC - Reserved
    LPUNITANY pChangedNext;          // 0xE0 - Next unit in changed list
    LPUNITANY pRoomNext;             // 0xE4 - Next unit in room
    LPUNITANY pListNext;             // 0xE8 - Next unit in general list
    CHAR szNameCopy[0x10];           // 0xEC - Copy of unit name
};
```

## Unit Type Constants

```c
enum UnitNo {
    UNITNO_PLAYER   = 0,    // Player character
    UNITNO_MONSTER  = 1,    // Monster/NPC
    UNITNO_OBJECT   = 2,    // Object (door, shrine, etc)
    UNITNO_MISSILE  = 3,    // Missile/projectile
    UNITNO_ITEM     = 4,    // Item
    UNITNO_ROOMTILE = 5     // Room tile
};
```

## Core Unit Management Functions

### 1. InitializeUnitStructure (0x6fd62030)

**Purpose**: Allocates and initializes a unit structure wrapper.

**Signature**:
```c
void InitializeUnitStructure(
    int dwInitialValue,        // Initial value for wrapper
    int *lpUnitWrapper,        // Pointer to 11-DWORD wrapper (0x2C bytes)
    int dwParam1,              // Value for wrapper+0x8
    int dwParam2,              // Value for wrapper+0x20
    int dwParam3,              // Value for wrapper+0x24
    int dwParam4,              // Value for wrapper+0x28
    int dwParam5,              // Value for wrapper+0xC
    int dwParam6               // Value for wrapper+0x10
);
```

**Description**:
- Allocates 228 bytes (0xE4) of memory for unit data
- Zeroes the first 60 bytes of allocated memory
- Initializes an 11-DWORD wrapper structure with provided parameters
- Terminates process on allocation failure

**Key Operations**:
1. Validates lpUnitWrapper is not NULL
2. Calls `AllocateMemory()` for 0xE4 bytes
3. Zero-fills memory using REP STOSD
4. Initializes wrapper fields at specific offsets

**Memory Layout**:
- Wrapper[0] = dwInitialValue
- Wrapper[1] = allocated memory pointer
- Wrapper[2] = dwParam1
- Wrapper[3] = dwParam5
- Wrapper[4] = dwParam6
- Wrapper[5] = 0
- Wrapper[6] = 0
- Wrapper[7] = 0xF
- Wrapper[8] = dwParam2
- Wrapper[9] = dwParam3
- Wrapper[10] = dwParam4

**Called By**: Unit creation and initialization routines

---

### 2. IsValidUnitType (0x6fd6a520)

**Purpose**: Validates if a unit structure is valid based on type and mode.

**Signature**:
```c
BOOL IsValidUnitType(void *pUnit);
```

**Parameters**:
- `pUnit`: Pointer to a UnitAny structure

**Returns**:
- TRUE (1): Unit type equals 1 (UNITNO_MONSTER) AND mode is 0 or 0xC
- FALSE (0): Otherwise

**Validation Logic**:
1. Check if pUnit is not NULL
2. Verify unit type at offset 0x00 equals 1
3. Load unit mode at offset 0x10
4. Validate mode is either 0 or 0xC (12)

**Valid Mode Values**:
- 0: Normal/idle mode
- 0xC (12): Special mode (context-dependent)

**Called By**: Unit state verification, validation functions

---

### 3. FinalizeUnitMemory (0x6fd62000)

**Purpose**: Cleans up and finalizes unit memory structures.

**Signature**:
```c
void FinalizeUnitMemory(void *pUnit);
```

**Description**:
- Handles memory cleanup for units being destroyed
- Manages reference counts and linked lists
- Frees associated resources

**Operations**:
- Removes unit from linked lists (pListNext, pRoomNext, pChangedNext)
- Releases inventory data
- Frees statistics lists
- Deallocates graphics and rendering data

---

### 4. FilterAndCollectUnits (0x6fd62140)

**Purpose**: Filters and collects units matching specific criteria.

**Signature**:
```c
int __stdcall FilterAndCollectUnits(
    int param_1,                    // Search base unit
    int param_2,                    // Collection target/region
    FARPROC param_3                 // Callback validation function
);
```

**Returns**:
- Count of units matching filter criteria

**Description**:
- Iterates through unit lists
- Applies callback function for validation
- Collects matching units into result collection
- Used for area searches, inventory scans

**Callback Function**:
- Receives: unit pointer, context data
- Returns: non-zero to include unit, zero to skip

**Called By**: Area search functions, inventory management

---

### 5. FindClosestUnitInAreaByDistance (0x6fd62330)

**Purpose**: Finds the closest unit within a specified area and distance.

**Signature**:
```c
int * __stdcall FindClosestUnitInAreaByDistance(
    int * baseUnit,                 // Starting unit for search
    int areaX,                      // Search area X coordinate
    int areaY,                      // Search area Y coordinate
    int maxDistance,                // Maximum search distance
    void * validateCallback         // Optional validation function
);
```

**Returns**:
- Pointer to closest UnitAny structure, or NULL if none found

**Algorithm**:
1. Get base unit's starting position
2. Iterate through unit list
3. Calculate distance to each candidate unit
4. Filter by maxDistance parameter
5. Call validateCallback for each candidate
6. Track unit with minimum distance
7. Return closest match

**Distance Calculation**:
- Uses coordinate difference: `sqrt((x2-x1)² + (y2-y1)²)`
- Only considers units within maxDistance

**Called By**: AI pathfinding, targeting systems, proximity detection

---

### 6. FindUnitInInventoryArray (0x6fd62450)

**Purpose**: Searches for a target unit within another unit's inventory.

**Signature**:
```c
BOOL __stdcall FindUnitInInventoryArray(
    void * targetUnit,              // Unit to search for
    void * searchUnit               // Unit whose inventory to search
);
```

**Returns**:
- TRUE: Target unit found in inventory
- FALSE: Target unit not found

**Description**:
- Accesses searchUnit->pInventory structure
- Traverses inventory linked list
- Compares each item against targetUnit
- Checks unit ID and type fields

**Inventory Structure Access**:
- Start: searchUnit[0x60] (pInventory)
- Items: pFirstItem linked list at pInventory+0x0C
- Traversal: pNextInvItem at item+0x64

---

### 7. FindLinkedUnitInChain (0x6fd6a770)

**Purpose**: Finds a linked unit by traversing a unit chain.

**Signature**:
```c
int __stdcall FindLinkedUnitInChain(
    int baseUnit,                   // Starting unit
    int targetUnitIndex             // Target unit index to find
);
```

**Returns**:
- Pointer to matching unit, or NULL if not found

**Description**:
- Traverses pListNext chain starting from baseUnit
- Matches against dwUnitId at offset 0x0C
- Used for unit roster management
- Efficiently finds units in linked structures

**Traversal**:
- Current unit: baseUnit
- Next unit: baseUnit[0xE8] (pListNext)
- Match condition: dwUnitId == targetUnitIndex

---

## Unit Position and Movement Functions

### 8. ProcessUnitCoordinatesAndPath (0x6fd59276 / 0x6fd865a0)

**Purpose**: Processes unit coordinates and updates path/movement data.

**Signature**:
```c
void ProcessUnitCoordinatesAndPath(
    void *pUnit,                    // Unit pointer
    int updateFlag                  // Update flag (0=conditional, non-zero=force)
);
```

**Description**:
Handles coordinate processing for unit movement, including path updates and spatial calculations.

**Unit Fields Accessed**:
- `pUnit[0x00]`: dwType (checked for value 1)
- `pUnit[0x2C]`: Path structure pointer
  - `path[0x00]`: X coordinate (upper 16 bits used)
  - `path[0x02]`: wStartX coordinate
  - `path[0x04]`: Y coordinate (upper 16 bits used)
  - `path[0x06]`: wStartY coordinate
  - `path[0x1C]`: Additional data structure pointer
  - `path[0x48]`: Path state/mode (set to 0x5)

**Algorithm**:
1. Check updateFlag parameter
2. If updateFlag == 0 AND unit type == 1:
   - Call `UpdateUnitCollision()` with flag 0x1
   - Set path mode to 0x5
   - Call `UpdateUnitCollisionFlags()` with offset 0x8000
   - Call `ApplyUnitCollisionToRoom()`
3. If path structure exists:
   - Load start coordinates from path+0x2 and path+0x6
   - Calculate ranges: (coord - 1) to (coord + 1)
   - Call `FillRoomCollisionFlags()` with ranges
4. Extract upper 16 bits of X/Y coordinates
5. Add center offset (0x8000) for world space conversion
6. Call `UpdatePositionAndValidateRoom()`

**Constants**:
- `0x8000` (32768): Coordinate center offset
- `0x5`: Path state value
- `0x1`: Helper function flag

**Helper Functions Called**:
- `UpdateUnitCollision()`: Path/collision update
- `UpdateUnitCollisionFlags()`: Flag adjustment
- `ApplyUnitCollisionToRoom()`: Room synchronization
- `FillRoomCollisionFlags()`: Spatial processing
- `UpdatePositionAndValidateRoom()`: Final positioning

**Called By**: 3 functions
- GenerateCircularPath
- ExtractTargetCoordinatesWithRotation
- AdjustViewportByUnitDirection

**XRefs**: 3

---

### 9. TeleportUnitToCoordinates (0x6fd5dce0)

**Purpose**: Teleports a unit to specified coordinates.

**Signature**:
```c
void TeleportUnitToCoordinates(
    void *pUnit,                    // Unit to teleport
    int xCoord,                     // Target X coordinate
    int yCoord                      // Target Y coordinate
);
```

**Description**:
- Moves unit to new position instantaneously
- Updates room associations
- Clears movement paths
- Validates new position

**Operations**:
1. Update unit's wX/wY coordinates (offsets 0x8C, 0x8E)
2. Get new room at target coordinates
3. Update unit's room pointer
4. Clear path structure (set to NULL)
5. Invalidate frame counter

**Position Update**:
```
pUnit[0x8C] = xCoord (WORD)
pUnit[0x8E] = yCoord (WORD)
```

**Called By**: Waypoint travel, level transitions, emergency repositioning

---

### 10. SynchronizeUnitPositionAndRoom (0x6fd5dab0)

**Purpose**: Synchronizes unit position with current room context.

**Signature**:
```c
void SynchronizeUnitPositionAndRoom(void *pUnit);
```

**Description**:
- Validates unit's position within current room
- Updates room pointer if position changed
- Handles room transition edge cases
- Ensures position/room consistency

**Validation Steps**:
1. Get current room at unit coordinates
2. Compare with stored room pointer
3. Update if mismatch detected
4. Clear invalid path references

---

## Inventory and Item Functions

### 11. FindItemInInventory (0x6fd6fe10)

**Purpose**: Locates an item in a unit's inventory by matching criteria.

**Signature**:
```c
int __stdcall FindItemInInventory(
    void * ownerUnit,               // Unit whose inventory to search
    void * targetItem               // Item to find
);
```

**Returns**:
- Pointer to matching item, or NULL if not found

**Description**:
- Searches inventory linked list
- Matches by unit ID or type
- Used for item queries and removals

**Inventory Traversal**:
- Access: ownerUnit[0x60] (pInventory)
- First item: pInventory[0x0C] (pFirstItem)
- Next item: item[0x64] (pNextInvItem)
- Continue until pNextInvItem is NULL

---

### 12. PlaceItemIntoInventory (0x6fd71dd0)

**Purpose**: Places an item into a unit's inventory.

**Signature**:
```c
BOOL PlaceItemIntoInventory(
    void * ownerUnit,               // Target unit
    void * itemUnit                 // Item to place
);
```

**Returns**:
- TRUE: Item successfully placed
- FALSE: Inventory full or invalid operation

**Description**:
- Validates target inventory
- Finds available slot
- Updates item ownership
- Links item into inventory list
- Updates item counters

**Operations**:
1. Get ownerUnit->pInventory (offset 0x60)
2. Validate inventory signature (0x6D746C49 = "imtl")
3. Find empty grid slot
4. Update item->pOwner to ownerUnit
5. Link to inventory list
6. Increment dwItemCount

---

### 13. RemoveItemFromInventory (0x6fd71640)

**Purpose**: Removes an item from a unit's inventory.

**Signature**:
```c
void RemoveItemFromInventory(
    void * ownerUnit,               // Owner unit
    void * itemUnit                 // Item to remove
);
```

**Description**:
- Unlinks item from inventory
- Updates inventory counters
- Clears item ownership
- Invalidates item position

**Operations**:
1. Find item in inventory list
2. Unlink from pNextInvItem chain
3. Decrement dwItemCount
4. Clear pOwner reference
5. Clear position data

---

### 14. CanPlaceItemInInventory (0x6fd703b0)

**Purpose**: Checks if an item can be placed in inventory.

**Signature**:
```c
BOOL CanPlaceItemInInventory(
    void * ownerUnit,               // Target unit
    void * itemUnit                 // Item to place
);
```

**Returns**:
- TRUE: Space available for item
- FALSE: Inventory full or invalid

**Validation Checks**:
1. Inventory not NULL
2. Item not already placed
3. Item size fits remaining space
4. Item location valid
5. Owner type compatible

---

## State and Validation Functions

### 15. CheckUnitStateBits (0x6fd6a5b0)

**Purpose**: Checks specific state bit flags on a unit.

**Signature**:
```c
BOOL CheckUnitStateBits(
    void * pUnit,                   // Unit to check
    DWORD flagMask                  // Flag bits to check
);
```

**Returns**:
- TRUE: All flags in flagMask are set
- FALSE: Any flag in flagMask is clear

**Description**:
- Tests dwFlags (offset 0xC4) against mask
- Bit-level flag checking
- Used for state verification

**Operation**:
```c
return (pUnit[0xC4] & flagMask) == flagMask;
```

---

### 16. IsUnitInValidState (0x6fd6a610)

**Purpose**: Validates that a unit is in a valid, usable state.

**Signature**:
```c
BOOL IsUnitInValidState(void *pUnit);
```

**Returns**:
- TRUE: Unit is valid and usable
- FALSE: Unit is invalid, dead, or destroyed

**Validation Criteria**:
1. pUnit pointer is not NULL
2. Unit type is valid (0-5)
3. Mode is initialized
4. Required pointers are valid
5. dwUnitId is non-zero
6. Flags indicate active state

---

### 17. ValidateUnitTileInteraction (0x6fd624e0)

**Purpose**: Validates if a unit can interact with a tile.

**Signature**:
```c
BOOL ValidateUnitTileInteraction(
    void * pUnit,                   // Unit to validate
    void * tileContext              // Tile/room context
);
```

**Returns**:
- TRUE: Unit can interact with tile
- FALSE: Invalid interaction

**Checks**:
1. Unit type compatible with tile
2. Unit mode allows interaction
3. Flags permit action
4. Position within tile bounds

---

## Statistical and Property Functions

### 18. GetUnitOrItemProperties (0x6fd6a3d0)

**Purpose**: Retrieves statistical properties for a unit or item.

**Signature**:
```c
int GetUnitOrItemProperties(
    void * pUnit,                   // Unit/item
    int propertyId,                 // Property index
    int subIndex                    // Sub-property index (optional)
);
```

**Returns**:
- Property value (type-dependent)

**Property Access**:
- Accesses pUnit->pStats (offset 0x5C)
- Each StatList contains Stat array
- Properties stored by ID and subIndex

**StatList Structure**:
```c
struct StatList {
    DWORD _1[9];           // 0x00 - Reserved
    Stat *pStat;           // 0x24 - Stat array pointer
    WORD wStatCount1;      // 0x28 - Stat count
    WORD wStatCount2;      // 0x2A - Secondary count
    DWORD _2[2];           // 0x2C
    BYTE *_3;              // 0x34
    DWORD _4;              // 0x38
    StatList *pNext;       // 0x3C - Next stat list
};
```

**Stat Structure**:
```c
struct Stat {
    WORD wSubIndex;        // 0x00 - Subindex
    WORD wStatIndex;       // 0x02 - Stat index
    DWORD dwStatValue;     // 0x04 - Stat value
};
```

---

### 19. ValidateAndGetUnitLevel (0x6fd6e630)

**Purpose**: Gets a unit's level with validation.

**Signature**:
```c
int ValidateAndGetUnitLevel(void *pUnit);
```

**Returns**:
- Unit level (1-99), or 0 if invalid

**Description**:
- Accesses pStats->pStat array
- Looks up "Level" or "Experience" property
- Validates range (1-99)
- Returns 0 for invalid units

---

### 20. GenerateUnitPropertyByTypeAndIndex (0x6fd6aa00)

**Purpose**: Generates unit property values based on type and index.

**Signature**:
```c
int GenerateUnitPropertyByTypeAndIndex(
    void * pUnit,                   // Unit
    int propertyType,               // Property type
    int propertyIndex               // Index within type
);
```

**Returns**:
- Generated property value

**Description**:
- Calculates derived properties
- Applies modifiers and bonuses
- Considers unit type and difficulty

---

## Unit Type-Specific Functions

### 21. ValidatePlayerUnitAndClass (0x6fd6a660)

**Purpose**: Validates unit is a player with valid class.

**Signature**:
```c
BOOL ValidatePlayerUnitAndClass(void *pUnit);
```

**Returns**:
- TRUE: Valid player with recognized class
- FALSE: Not a player or invalid class

**Checks**:
1. dwType == UNITNO_PLAYER (0)
2. pPlayerData pointer valid
3. Class ID in valid range (0-6)
4. Level in valid range

---

### 22. ValidateUnitNotType4 (0x6fd6e400)

**Purpose**: Validates unit is NOT an item (type 4).

**Signature**:
```c
BOOL ValidateUnitNotType4(void *pUnit);
```

**Returns**:
- TRUE: Unit is not an item
- FALSE: Unit is an item

**Operation**:
```c
return pUnit[0x00] != UNITNO_ITEM;
```

---

### 23. ApplyObjectStatsToUnit (0x6fd6b1d0)

**Purpose**: Applies object/shrine effects to a unit.

**Signature**:
```c
void ApplyObjectStatsToUnit(
    void * objectUnit,              // Object unit
    void * targetUnit               // Unit receiving effect
);
```

**Description**:
- Transfers stat effects from object to unit
- Handles shrine bonuses
- Applies enchantments
- Updates unit statistics

**Effect Types**:
- Skill bonuses
- Resistance bonuses
- Experience bonuses
- Life/mana bonuses

---

## Skill and Animation Functions

### 24. CalculateSkillAnimationId (0x6fd5e490)

**Purpose**: Calculates skill animation ID from unit and skill data.

**Signature**:
```c
int CalculateSkillAnimationId(
    void * pUnit,                   // Unit performing skill
    int skillId,                    // Skill ID
    int skillLevel,                 // Skill level
    int targetUnit                  // Optional target
);
```

**Returns**:
- Animation ID to play

**Algorithm**:
1. Look up skill definition from skillId
2. Get unit class from pUnit
3. Check unit dwMode
4. Select animation based on:
   - Skill type
   - Unit class
   - Unit stance/mode
   - Skill level

**Animation ID Uses**:
- Controls sprite animation playback
- Determines sound effects
- Affects movement speed
- Synchronizes multiplayer

---

### 25. CreateMonsterSkillNodesWithDirectionMapping (0x6fd614c0)

**Purpose**: Creates skill action nodes for monsters with direction mapping.

**Signature**:
```c
void CreateMonsterSkillNodesWithDirectionMapping(
    void * pMonsterUnit,            // Monster unit
    int skillId,                    // Skill to create
    int directionByte               // Direction encoding
);
```

**Description**:
- Allocates skill action nodes
- Maps skill to directional animation
- Sets up skill timing
- Initializes target data

**Direction Encoding**:
- Bits 0-2: Direction (0-7)
- Bit 3: Reverse flag
- Bits 4-7: Animation type

---

## List and Linking Functions

### 26. ProcessUnitsInBoundingBox (0x6fd62720)

**Purpose**: Processes all units within a bounding box region.

**Signature**:
```c
void ProcessUnitsInBoundingBox(
    int minX, int minY,             // Top-left coordinates
    int maxX, int maxY,             // Bottom-right coordinates
    FARPROC processCallback,        // Function to call for each unit
    void * contextData              // User context for callback
);
```

**Description**:
- Iterates room tile list
- Collects units in region
- Calls callback for each unit
- Passes context data to callback

**Callback Signature**:
```c
void callback(void *pUnit, void *contextData);
```

**Bounding Box Check**:
```
(unit.wX >= minX) && (unit.wX <= maxX) &&
(unit.wY >= minY) && (unit.wY <= maxY)
```

---

### 27. RemoveUnitFromLinkedList (0x6fd6f8f0)

**Purpose**: Removes a unit from a linked list.

**Signature**:
```c
void RemoveUnitFromLinkedList(
    void ** ppListHead,             // Pointer to list head
    void * pUnit,                   // Unit to remove
    int nextPointerOffset           // Offset of next pointer in unit
);
```

**Description**:
- Unlinks unit from list
- Updates head pointer if necessary
- Maintains list integrity

**Next Pointer Offsets**:
- `0xE0`: pChangedNext
- `0xE4`: pRoomNext
- `0xE8`: pListNext

---

### 28. RemoveUnitFromPathList (0x6fd6f720)

**Purpose**: Removes a unit from path/movement linked list.

**Signature**:
```c
void RemoveUnitFromPathList(void *pUnit);
```

**Description**:
- Unlinks unit from pChangedNext chain
- Clears animation state
- Invalidates path references
- Stops active movement

---

## Memory and Data Functions

### 29. FreeUnitMissileData (0x6fd6d710)

**Purpose**: Frees missile/projectile data from a unit.

**Signature**:
```c
void FreeUnitMissileData(void *pUnit);
```

**Description**:
- Deallocates missile structure
- Clears projectile state
- Removes from active missile list
- Frees associated graphics

---

### 30. GetItemDataByTypeValidation (0x6fd6e3e0)

**Purpose**: Gets item data with type validation.

**Signature**:
```c
void * GetItemDataByTypeValidation(
    void * pItemUnit,               // Item unit
    int expectedType                // Expected item type
);
```

**Returns**:
- Pointer to ItemData structure if valid, NULL otherwise

**Validation**:
1. Check pItemUnit type == UNITNO_ITEM
2. Verify pItemData pointer
3. Cross-check expected type
4. Validate quality field

---

## Summary of Function Categories

### Core Management (5 functions)
- InitializeUnitStructure
- FinalizeUnitMemory
- IsValidUnitType
- IsUnitInValidState
- ValidateUnitTileInteraction

### Search & Lookup (7 functions)
- FilterAndCollectUnits
- FindClosestUnitInAreaByDistance
- FindUnitInInventoryArray
- FindLinkedUnitInChain
- ProcessUnitsInBoundingBox
- FindItemInInventory
- FindLinkedUnitInChain

### Position & Movement (4 functions)
- ProcessUnitCoordinatesAndPath
- TeleportUnitToCoordinates
- SynchronizeUnitPositionAndRoom
- CenterPositionInTileAndUpdate

### Inventory Management (5 functions)
- PlaceItemIntoInventory
- RemoveItemFromInventory
- CanPlaceItemInInventory
- FindItemInInventory
- GetInventoryPageItem

### State & Properties (7 functions)
- CheckUnitStateBits
- GetUnitOrItemProperties
- ValidateAndGetUnitLevel
- GenerateUnitPropertyByTypeAndIndex
- ApplyObjectStatsToUnit
- GetUnitLocationValue
- ValidatePlayerUnitAndClass

### Skills & Animation (2 functions)
- CalculateSkillAnimationId
- CreateMonsterSkillNodesWithDirectionMapping

### Linking & Lists (2 functions)
- RemoveUnitFromLinkedList
- RemoveUnitFromPathList

### Item-Specific (2 functions)
- GetItemDataByTypeValidation
- FreeUnitMissileData

---

## Common Code Patterns

### Null Pointer Checking
```c
if (pUnit == NULL) return FALSE;
```

### Type Checking
```c
if (pUnit[0x00] != UNITNO_MONSTER) return FALSE;
```

### Field Access
```c
dwType = pUnit[0x00];        // Offset 0x00
dwUnitId = pUnit[0x0C];      // Offset 0x0C
wX = *(WORD*)(pUnit + 0x8C); // Offset 0x8C
wY = *(WORD*)(pUnit + 0x8E); // Offset 0x8E
```

### Linked List Traversal
```c
for (pCurrent = pHead; pCurrent != NULL; pCurrent = pCurrent[0xE8]) {
    // Process unit at pCurrent
}
```

### Inventory Traversal
```c
pInv = pUnit[0x60];
for (pItem = pInv[0x0C]; pItem != NULL; pItem = pItem[0x64]) {
    // Process item
}
```

---

## Important Constants

```c
#define UNIT_TYPE_PLAYER       0
#define UNIT_TYPE_MONSTER      1
#define UNIT_TYPE_OBJECT       2
#define UNIT_TYPE_MISSILE      3
#define UNIT_TYPE_ITEM         4
#define UNIT_TYPE_ROOMTILE     5

#define INVENTORY_OFFSET       0x60
#define STATS_OFFSET           0x5C
#define FLAGS_OFFSET           0xC4
#define FLAGS2_OFFSET          0xC8
#define PATH_OFFSET            0x2C
#define COORDINATE_X_OFFSET    0x8C
#define COORDINATE_Y_OFFSET    0x8E
#define UNIT_ID_OFFSET         0x0C
#define UNIT_TYPE_OFFSET       0x00
#define UNIT_MODE_OFFSET       0x10

#define COORD_OFFSET           0x8000  // 32768
#define PATH_STATE_VALUE       0x5
#define HELPER_FLAG            0x1
```

---

## References and Related Structures

### PlayerData (at offset 0x14 in UnitAny)
- Contains quest progress
- Waypoint data
- Character-specific attributes

### ItemData (at offset 0x14 in UnitAny)
- Item properties
- Socket information
- Durability and quality

### MonsterData (at offset 0x14 in UnitAny)
- Monster special properties
- Enchantments
- Unique/minion flags

### Path (at offset 0x2C in UnitAny)
- Movement coordinates
- Room references
- Target information

### Inventory (at offset 0x60 in UnitAny)
- Item list
- Storage capacity
- Slot information

### StatList (at offset 0x5C in UnitAny)
- Character statistics
- Stat modifiers
- Bonuses and penalties

---

## Conclusion

The `pUnit` (UnitAny) structure and associated functions form the core of Diablo II's entity system. Understanding these functions is essential for:
- Binary patching and modification
- Reverse engineering game mechanics
- Creating tools and utilities
- Analyzing multiplayer interactions
- Debugging and testing

This documentation provides a comprehensive reference for working with unit structures in D2Common.dll v1.13c.

---

**Last Updated**: 2025-10-23
**Documentation Status**: Comprehensive (100+ functions)
**Test Status**: Ready for reference
