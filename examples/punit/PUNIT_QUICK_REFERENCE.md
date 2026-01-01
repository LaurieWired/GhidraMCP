# pUnit (UnitAny) Quick Reference Guide

## UnitAny Structure Overview

```
Offset  Size  Field                    Type            Purpose
------  ----  -----                    ----            -------
0x00    4     dwType                   DWORD           Unit type (0-5)
0x04    4     dwTxtFileNo              DWORD           TXT record index
0x08    4     _reserved1               DWORD
0x0C    4     dwUnitId                 DWORD           Unique unit ID
0x10    4     dwMode                   DWORD           Unit mode/state
0x14    4     pData (union)            PTR             Type-specific data
0x18    4     dwAct                    DWORD           Act index
0x1C    4     pAct                     PTR             Act structure
0x20    8     dwSeed[2]                DWORD[2]        Random seed
0x28    4     _reserved2               DWORD
0x2C    4     pPath (union)            PTR             Path/movement data
0x30    20    _reserved3               DWORD[5]
0x44    4     dwGfxFrame               DWORD           Animation frame
0x48    4     dwFrameRemain            DWORD           Frames remaining
0x4C    2     wFrameRate               WORD            Frame rate
0x4E    2     _reserved4               WORD
0x50    4     pGfxUnk                  PTR             Graphics data
0x54    4     pGfxInfo                 PTR             Graphics info
0x58    4     _reserved5               DWORD
0x5C    4     pStats                   PTR             Statistics list
0x60    4     pInventory               PTR             Inventory
0x64    4     ptLight                  PTR             Light structure
0x68    36    _reserved6               DWORD[9]
0x8C    2     wX                       WORD            X coordinate
0x8E    2     wY                       WORD            Y coordinate
0x90    4     _reserved7               DWORD
0x94    4     dwOwnerType              DWORD           Owner type
0x98    4     dwOwnerId                DWORD           Owner ID
0x9C    8     _reserved8               DWORD[2]
0xA4    4     pOMsg                    PTR             Overhead message
0xA8    4     pInfo                    PTR             Skill/action info
0xAC    24    _reserved9               DWORD[6]
0xC4    4     dwFlags                  DWORD           Flags
0xC8    4     dwFlags2                 DWORD           Flags 2
0xCC    20    _reserved10              DWORD[5]
0xE0    4     pChangedNext             PTR             Next in change list
0xE4    4     pRoomNext                PTR             Next in room
0xE8    4     pListNext                PTR             Next in general list
0xEC    16    szNameCopy               CHAR[16]        Name copy
```

## Unit Types

| Value | Name       | Description | Type Field | Data Union |
|-------|-----------|-------------|------------|-----------|
| 0 | PLAYER | Player character | - | pPlayerData |
| 1 | MONSTER | Monster/NPC | - | pMonsterData |
| 2 | OBJECT | Door, shrine, etc | - | pObjectData |
| 3 | MISSILE | Projectile/spell | - | (missile-specific) |
| 4 | ITEM | Item object | - | pItemData |
| 5 | ROOMTILE | Dungeon tile | - | (tile-specific) |

## Most Common Functions

### Finding Units
```c
FilterAndCollectUnits()         // Filter/collect by criteria
FindClosestUnitInAreaByDistance() // Find nearest in range
FindUnitInInventoryArray()      // Check inventory contents
FindLinkedUnitInChain()         // Search unit list by ID
ProcessUnitsInBoundingBox()     // Process region
```

### Managing Units
```c
InitializeUnitStructure()       // Create new unit
FinalizeUnitMemory()            // Destroy unit
TeleportUnitToCoordinates()     // Move unit instantly
SynchronizeUnitPositionAndRoom() // Update position
```

### Inventory Management
```c
PlaceItemIntoInventory()        // Add item
RemoveItemFromInventory()       // Remove item
FindItemInInventory()           // Search inventory
CanPlaceItemInInventory()       // Check space
```

### Validation
```c
IsValidUnitType()               // Verify unit
IsUnitInValidState()            // Check usable
ValidatePlayerUnitAndClass()    // Check player
CheckUnitStateBits()            // Test flags
```

### Properties
```c
GetUnitOrItemProperties()       // Get stats
ValidateAndGetUnitLevel()       // Get level
GenerateUnitPropertyByTypeAndIndex() // Calculate property
ApplyObjectStatsToUnit()        // Apply effects
```

### Position/Path
```c
ProcessUnitCoordinatesAndPath() // Update position
GetRoomAtCoordinates()          // Get room from coords
ValidateUnitPositionOrDistance() // Verify distance
```

## Quick Code Patterns

### Null Check
```c
if (!pUnit) return FALSE;
```

### Type Check
```c
if (pUnit[0x00] != UNITNO_MONSTER) return FALSE;
```

### Get Coordinate
```c
int x = *(WORD*)(pUnit + 0x8C);
int y = *(WORD*)(pUnit + 0x8E);
```

### Get Unit ID
```c
DWORD unitId = *(DWORD*)(pUnit + 0x0C);
```

### Get Inventory
```c
Inventory *pInv = *(Inventory**)(pUnit + 0x60);
```

### Get Stats
```c
StatList *pStats = *(StatList**)(pUnit + 0x5C);
```

### Traverse Units in List
```c
for (pCurr = pHead; pCurr; pCurr = *(void**)(pCurr + 0xE8)) {
    // Process pCurr
}
```

### Traverse Inventory Items
```c
Inventory *pInv = *(Inventory**)(pUnit + 0x60);
for (pItem = *(void**)(pInv + 0x0C); pItem;
     pItem = *(void**)(pItem + 0x64)) {
    // Process pItem
}
```

## Flag Offsets

```
0xC4  dwFlags      Primary unit flags
0xC8  dwFlags2     Secondary unit flags
```

## Important Addresses

```
InitializeUnitStructure      @ 0x6fd62030
FinalizeUnitMemory           @ 0x6fd62000
IsValidUnitType              @ 0x6fd6a520
IsUnitInValidState           @ 0x6fd6a610
FilterAndCollectUnits        @ 0x6fd62140
FindClosestUnitInAreaByDistance @ 0x6fd62330
FindUnitInInventoryArray     @ 0x6fd62450
FindLinkedUnitInChain        @ 0x6fd6a770
ProcessUnitCoordinatesAndPath @ 0x6fd59276 (thunk) / 0x6fd865a0 (impl)
TeleportUnitToCoordinates    @ 0x6fd5dce0
SynchronizeUnitPositionAndRoom @ 0x6fd5dab0
FindItemInInventory          @ 0x6fd6fe10
PlaceItemIntoInventory       @ 0x6fd71dd0
RemoveItemFromInventory      @ 0x6fd71640
CanPlaceItemInInventory      @ 0x6fd703b0
CheckUnitStateBits           @ 0x6fd6a5b0
GetUnitOrItemProperties      @ 0x6fd6a3d0
ValidateAndGetUnitLevel      @ 0x6fd6e630
GenerateUnitPropertyByTypeAndIndex @ 0x6fd6aa00
ApplyObjectStatsToUnit       @ 0x6fd6b1d0
CalculateSkillAnimationId    @ 0x6fd5e490
CreateMonsterSkillNodes      @ 0x6fd614c0
ProcessUnitsInBoundingBox    @ 0x6fd62720
RemoveUnitFromLinkedList     @ 0x6fd6f8f0
RemoveUnitFromPathList       @ 0x6fd6f720
ValidatePlayerUnitAndClass   @ 0x6fd6a660
ValidateUnitTileInteraction  @ 0x6fd624e0
```

## Constant Values

```c
#define COORD_OFFSET           0x8000
#define PATH_STATE             0x5
#define HELPER_FLAG            0x1

// Mode values (at offset 0x10)
#define MODE_NORMAL            0
#define MODE_SPECIAL           0xC
```

## Error Codes

When using `GetErrorMessageString()`:
```c
0xE2  // lpUnitWrapper is NULL
0xE5  // Memory allocation failed
```

## Related Structures

### PlayerData (at [pUnit + 0x14])
- Quest progression
- Waypoint status
- Class-specific data

### ItemData (at [pUnit + 0x14])
- Item properties
- Socket information
- Durability

### MonsterData (at [pUnit + 0x14])
- Unique properties
- Enchantments
- Monster modes

### Path (at [pUnit + 0x2C])
- Movement target
- Room reference
- Coordinate data

### Inventory (at [pUnit + 0x60])
- Item list head
- Item count
- Slot information

### StatList (at [pUnit + 0x5C])
- Stat array pointer
- Stat count
- Modifier chains

## Common Tasks

### Create a Unit
```c
int wrapper[11];
InitializeUnitStructure(
    initialValue,
    wrapper,
    param1, param2, param3, param4, param5, param6
);
UnitAny *pUnit = (UnitAny*)wrapper[1];
```

### Check if Player
```c
BOOL isPlayer = (pUnit[0x00] == UNITNO_PLAYER);
```

### Move Unit
```c
TeleportUnitToCoordinates(pUnit, newX, newY);
```

### Add Item to Inventory
```c
BOOL success = PlaceItemIntoInventory(ownerUnit, itemUnit);
```

### Get Unit Level
```c
int level = ValidateAndGetUnitLevel(pUnit);
```

### Find Nearby Unit
```c
UnitAny *closest = FindClosestUnitInAreaByDistance(
    baseUnit, centerX, centerY, maxDistance, NULL
);
```

### Process All Units in Area
```c
ProcessUnitsInBoundingBox(minX, minY, maxX, maxY,
                          callback_func, context);
```

## Debugging Tips

1. **Verify Unit Pointer**: Always null-check before access
2. **Check Unit Type**: Verify dwType before accessing type-specific data
3. **Validate Pointers**: Check pStats, pInventory before dereference
4. **Use IsValidUnitType()**: Before complex operations
5. **Trace Linked Lists**: Use pListNext/pRoomNext for iteration
6. **Monitor Coordinates**: wX/wY at 0x8C/0x8E
7. **Check Mode**: dwMode at 0x10 for state validation

## Performance Notes

- Linked list traversal: O(n) complexity
- Inventory search: Linear through items
- Spatial queries: Use bounding box for efficiency
- StatList lookup: May require linear search
- Multiple iterations: Cache pointers when possible

---

**For detailed information**, see `PUNIT_FUNCTIONS_DOCUMENTATION.md`
