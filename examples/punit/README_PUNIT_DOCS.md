# pUnit (UnitAny) Documentation Suite

## Overview

This documentation suite provides comprehensive coverage of all functions that use the `pUnit` structure (typedef'd as `UnitAny*`) in Diablo II's D2Common.dll binary.

**Scope**: Diablo II v1.13c
**Binary**: D2Common.dll
**Functions Documented**: 100+ functions
**Date**: 2025-10-23

## Documentation Files

### 1. **PUNIT_FUNCTIONS_DOCUMENTATION.md** ⭐ MAIN REFERENCE
   - **Purpose**: Complete, detailed documentation
   - **Content**: 30+ key functions with full decompilation analysis
   - **Includes**: Structure definitions, algorithms, parameters, usage
   - **Best For**: Deep understanding, implementation details
   - **Length**: Comprehensive

### 2. **PUNIT_QUICK_REFERENCE.md** ⭐ QUICK LOOKUP
   - **Purpose**: Fast reference for common tasks
   - **Content**: Function signatures, code patterns, constants
   - **Includes**: Quick copy-paste code, struct offsets, addresses
   - **Best For**: Quick lookups, common patterns
   - **Length**: Concise

### 3. **PUNIT_FUNCTION_INDEX.md** ⭐ FUNCTION LISTING
   - **Purpose**: Complete function index organized by category
   - **Content**: All 100+ functions with address, xref count, description
   - **Includes**: Category organization, function metadata
   - **Best For**: Finding specific functions, browsing by category
   - **Length**: Reference tables

## Structure Overview

The UnitAny structure is a 244-byte (0xF4) universal entity descriptor used for players, monsters, items, objects, and more.

### Key Fields:
```
Offset  Size  Field              Type        Purpose
0x00    4     dwType             DWORD       Unit type (0-5)
0x0C    4     dwUnitId           DWORD       Unique ID
0x8C    2     wX                 WORD        X coordinate
0x8E    2     wY                 WORD        Y coordinate
0xC4    4     dwFlags            DWORD       Status flags
```

**Full structure layout** available in `PUNIT_FUNCTIONS_DOCUMENTATION.md`

## Function Categories

### Core Management (10 functions)
Initialize, finalize, validate units; type checking, state validation

### Search & Discovery (8 functions)
Find units by distance, ID, location; filter and collect operations

### Position & Movement (15 functions)
Coordinate processing, pathfinding; teleportation, room synchronization

### Inventory & Items (40 functions)
Place/remove items; inventory searches; item data manipulation

### Statistics & Properties (15 functions)
Get/set unit properties; stat queries, level access; data table operations

### Skills & Animation (4 functions)
Animation ID calculation; skill node creation; skill timing

### Linked Lists (3 functions)
Unit list management; linked structure traversal

### Type-Specific (5 functions)
Monster, player, item specific; type conversions

## Most Frequently Referenced Functions

| Function | Address | XRefs | Purpose |
|----------|---------|-------|---------|
| GetRoomAtCoordinates | 0x6fd51330 | 54 | Spatial queries |
| CalculateSkillAnimationId | 0x6fd5e490 | 88 | Animation handling |
| MultiplyDivideSafe | 0x6fd511e0 | 43 | Math utility |
| WriteBitsToStream | 0x6fd592c4 | 83 | I/O operations |

## Common Use Cases

### Finding Units
```c
// Find closest unit in range
UnitAny *closest = FindClosestUnitInAreaByDistance(
    baseUnit, centerX, centerY, maxDistance, NULL
);

// Find unit by ID in list
int result = FindLinkedUnitInChain(baseUnit, targetId);

// Collect all units matching criteria
FilterAndCollectUnits(baseUnit, collection, callback);
```

### Managing Inventory
```c
// Add item to inventory
BOOL success = PlaceItemIntoInventory(ownerUnit, itemUnit);

// Remove item from inventory
RemoveItemFromInventory(ownerUnit, itemUnit);

// Search for item
UnitAny *item = FindItemInInventory(ownerUnit, searchItem);
```

### Position & Movement
```c
// Teleport unit
TeleportUnitToCoordinates(pUnit, newX, newY);

// Process position updates
ProcessUnitCoordinatesAndPath(pUnit, updateFlag);

// Sync position with room
SynchronizeUnitPositionAndRoom(pUnit);
```

### State Verification
```c
// Check unit validity
if (IsValidUnitType(pUnit)) { /* ... */ }

// Check specific flags
if (CheckUnitStateBits(pUnit, flagMask)) { /* ... */ }

// Get unit level
int level = ValidateAndGetUnitLevel(pUnit);
```

## Key Constants

```c
// Unit Types
#define UNITNO_PLAYER       0
#define UNITNO_MONSTER      1
#define UNITNO_OBJECT       2
#define UNITNO_MISSILE      3
#define UNITNO_ITEM         4
#define UNITNO_ROOMTILE     5

// Field Offsets
#define TYPE_OFFSET         0x00
#define UNITID_OFFSET       0x0C
#define MODE_OFFSET         0x10
#define COORDX_OFFSET       0x8C
#define COORDY_OFFSET       0x8E
#define FLAGS_OFFSET        0xC4
#define INVENTORY_OFFSET    0x60
#define STATS_OFFSET        0x5C
#define PATH_OFFSET         0x2C

// Special Values
#define COORD_CENTER_OFFSET 0x8000
#define PATH_STATE_VALUE    0x5
```

## Quick Navigation

### By Function Name
→ Use `PUNIT_FUNCTION_INDEX.md`

### By Category
→ Use `PUNIT_QUICK_REFERENCE.md` or `PUNIT_FUNCTION_INDEX.md`

### By Address
→ Use `PUNIT_FUNCTION_INDEX.md` (with addresses)

### Detailed Implementation
→ Use `PUNIT_FUNCTIONS_DOCUMENTATION.md`

### Code Examples
→ Use `PUNIT_QUICK_REFERENCE.md`

## Related Files

- `examples/D2Structs.h` - Original struct definitions
- `bridge_mcp_ghidra.py` - Ghidra MCP bridge
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` - Plugin source

## Using These Docs with Ghidra

1. Open binary in Ghidra
2. Use address from docs to navigate:
   - Ctrl+G (Go to Address)
   - Enter address from docs
3. Review function in Decompiler window
4. Compare with documentation
5. Set breakpoints or modify as needed

## Common Issues & Solutions

### Issue: "Unit pointer is NULL"
- **Solution**: Always check `if (pUnit == NULL)` before operations
- **Reference**: See validation functions in docs

### Issue: "Can't find item in inventory"
- **Solution**: Verify inventory pointer at `pUnit[0x60]`
- **Reference**: See `PUNIT_QUICK_REFERENCE.md`

### Issue: "Unit type mismatch"
- **Solution**: Check `pUnit[0x00]` against expected type
- **Reference**: See Unit Types section

### Issue: "Position not updating"
- **Solution**: Call `SynchronizeUnitPositionAndRoom()` after movement
- **Reference**: See Position & Movement functions

## Terminology

| Term | Definition |
|------|-----------|
| pUnit | Pointer to UnitAny structure |
| dwType | DWORD unit type field |
| dwUnitId | Unique unit identifier |
| wX, wY | Word (16-bit) coordinates |
| pListNext | Next unit in linked list |
| pInventory | Inventory structure pointer |
| pStats | Statistics list pointer |

## Development Tips

1. **Verify Structure Layout**: Always confirm offset values
2. **Type Checking**: Validate unit type before type-specific access
3. **Null Checks**: Always check pointers before dereference
4. **List Traversal**: Use pListNext/pRoomNext for iteration
5. **Coordinate System**: Remember 0x8000 center offset
6. **Inventory**: Access items through pFirstItem chain
7. **Stats**: Query properties through StatList

## Performance Considerations

- Linked list traversal is O(n)
- Inventory searches are linear
- Use spatial queries for efficiency
- Cache pointers when iterating multiple times
- Consider callback functions for batch processing

## Reverse Engineering Notes

These functions represent the core of Diablo II's entity system:
- Universal unit handling (all entity types)
- Flexible property system (stats/affections)
- Dynamic memory management
- Efficient linked-list structures
- Coordinate-based spatial system

## Documentation Quality

- **Function Coverage**: 100+ functions documented
- **Code Analysis**: Complete decompilation analysis
- **Struct Layout**: Full offset documentation
- **Examples**: Practical code examples included
- **Cross-References**: XRef counts provided
- **Category Organization**: Logical grouping

## Version Information

- **Diablo II Version**: 1.13c
- **Binary**: D2Common.dll
- **Analysis Tool**: Ghidra 11.4.2
- **Documentation Date**: 2025-10-23
- **Status**: Complete and Current

## How to Update

When analyzing new functions:
1. Use Ghidra to decompile function
2. Copy relevant details to appropriate doc
3. Cross-reference with similar functions
4. Add to function index with address/xref count
5. Update category summary if new category discovered

---

**Created with Ghidra MCP Tools**
**Last Updated**: 2025-10-23
**Status**: Complete Reference Suite
