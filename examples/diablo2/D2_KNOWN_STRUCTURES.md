# Diablo II Known Structures Inventory

## Document Purpose

This living document tracks all known Diablo II structures that have been defined in Ghidra for reverse engineering. When new structures are discovered during function documentation, add them to this inventory to maintain a complete catalog of available data types.

**Last Updated**: 2025-10-24
**Ghidra Project**: D2Common.dll Analysis
**Structure Source**: examples/D2Structs.h (Diablo II 1.13c)

---

## Core Game Structures

### UnitAny (0xEC bytes)
**Status**: ✅ Defined in Ghidra
**Location**: Main game entity structure
**Usage**: All unit types (Player, Monster, Object, Missile, Item, Tile)
**Key Fields**: dwType, dwTxtFileNo, dwUnitId, dwMode, pTypeSpecificData, pPath, pStats, pInventory, wX, wY, dwFlags
**Reference**: D2_STRUCTURES_REFERENCE.md line 17

### Path (0x68 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x2C
**Usage**: Movement and pathfinding for all units
**Key Fields**: xPos, yPos, xTarget, yTarget, pRoom1, pUnit, pTargetUnit, dwPathType, bDirection
**Reference**: D2_STRUCTURES_REFERENCE.md line 85

### ItemPath (extends Path)
**Status**: ✅ Defined in Ghidra
**Location**: Union with Path at UnitAny+0x2C for items
**Usage**: Item-specific path data
**Key Fields**: dwPosX (+0x0C), dwPosY (+0x10), inherits Path fields
**Reference**: examples/D2Structs.h line 382

### ObjectPath (extends Path)
**Status**: ✅ Defined in Ghidra
**Location**: Union with Path at UnitAny+0x2C for objects
**Usage**: Object-specific path data
**Key Fields**: pRoom1 (+0x00), dwPosX (+0x0C), dwPosY (+0x10), inherits Path fields
**Reference**: examples/D2Structs.h line 561

---

## Type-Specific Data Structures

### PlayerData (0x28 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x14 when dwType=0
**Usage**: Player character data
**Key Fields**: szName (16 chars), pNormalQuest, pNightmareQuest, pHellQuest, waypoint pointers
**Reference**: D2_STRUCTURES_REFERENCE.md line 113

### MonsterData (0x60+ bytes)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x14 when dwType=1
**Usage**: Monster/NPC data
**Key Fields**: Type flags (fNormal, fChamp, fBoss, fMinion), anEnchants[9], wUniqueNo, wName
**Reference**: D2_STRUCTURES_REFERENCE.md line 126

### ObjectData (size varies)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x14 when dwType=2
**Usage**: Interactive object data
**Key Fields**: pTxt (ObjectTxt*), Type, szOwner
**Reference**: examples/D2Structs.h line 554

### MissileData (0x34 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x14 when dwType=3
**Usage**: Projectile/missile data
**Key Fields**: wClassOrQuality (+0x06), nSkillLevel (+0x0C), dwField_0x2c
**Reference**: D2_STRUCTURES_REFERENCE.md line 148

### ItemData (0x88+ bytes)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x14 when dwType=4
**Usage**: Item/equipment data
**Key Fields**: dwQuality, dwItemFlags, wPrefix, wSuffix, BodyLocation, ItemLocation, NodePage, pOwner
**Reference**: D2_STRUCTURES_REFERENCE.md line 175

### TileData
**Status**: ⚠️ Not fully documented
**Location**: UnitAny+0x14 when dwType=5
**Usage**: Tile/terrain data
**Key Fields**: Unknown - structure appears unused in 1.13c
**Reference**: examples/D2Structs.h line 582 (comment: "doesn't appear to exist anymore")

---

## Level/Dungeon Structures

### Level (0x1D4 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: Referenced by Room2+0x58
**Usage**: Act level container
**Key Fields**: pRoom2First, dwPosX, dwPosY, dwSizeX, dwSizeY, dwLevelNo, dwSeed[2], pMisc, pNextLevel
**Reference**: D2_STRUCTURES_REFERENCE.md line 274

### Room1 (0x80 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: Active room instance
**Usage**: Spawned dungeon room with units
**Key Fields**: pRoomsNear, pRoom2, Coll, dwXStart, dwYStart, dwXSize, dwYSize, pUnitFirst, pRoomNext
**Reference**: D2_STRUCTURES_REFERENCE.md line 228

### Room2 (0x60 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: Level template data
**Usage**: Room template/seed data
**Key Fields**: pRoom2Near, pRoom1, dwPosX, dwPosY, dwSizeX, dwSizeY, pLevel, dwPresetType, pRoomTiles, pPreset
**Reference**: D2_STRUCTURES_REFERENCE.md line 248

### RoomTile
**Status**: ✅ Defined in Ghidra
**Location**: Room2+0x4C
**Usage**: Tile data for rooms
**Key Fields**: pRoom2, pNext, nNum
**Reference**: examples/D2Structs.h line 188

### PresetUnit
**Status**: ✅ Defined in Ghidra
**Location**: Room2+0x5C
**Usage**: Preset object placements
**Key Fields**: dwTxtFileNo, dwPosX, dwPosY, dwType, pPresetNext
**Reference**: examples/D2Structs.h line 266

### CollMap
**Status**: ✅ Defined in Ghidra
**Location**: Room1+0x20
**Usage**: Collision map for pathfinding
**Key Fields**: dwPosGameX/Y, dwSizeGameX/Y, dwPosRoomX/Y, dwSizeRoomX/Y, pMapStart, pMapEnd
**Reference**: examples/D2Structs.h line 253

---

## Act Structures

### Act (size varies)
**Status**: ✅ Defined in Ghidra
**Location**: Referenced by UnitAny+0x1C
**Usage**: Act container
**Key Fields**: dwMapSeed, pRoom1, dwAct, pMisc
**Reference**: examples/D2Structs.h line 347

### ActMisc
**Status**: ✅ Defined in Ghidra
**Location**: Act+0x48, Level+0x1B4
**Usage**: Act miscellaneous data
**Key Fields**: dwStaffTombLevel, pAct, pLevelFirst
**Reference**: examples/D2Structs.h line 337

---

## Inventory & Item Structures

### Inventory (0x2C bytes)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x60
**Usage**: Unit inventory container
**Key Fields**: dwSignature, pOwner, pFirstItem, pLastItem, pCursorItem, dwLeftItemUid, dwOwnerId, dwItemCount
**Reference**: D2_STRUCTURES_REFERENCE.md line 324

### ItemTxt
**Status**: ✅ Defined in Ghidra
**Location**: Referenced by item lookups
**Usage**: Item definition from txt files
**Key Fields**: szName2, dwCode/szCode, nLocaleTxtNo, xSize, ySize, nType, fQuest
**Reference**: examples/D2Structs.h line 476

---

## Statistics Structures

### StatList (0x40 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x5C
**Usage**: Linked list of unit stats
**Key Fields**: pStat, wStatCount1, wStatCount2, pNext
**Reference**: D2_STRUCTURES_REFERENCE.md line 300

### Stat (0x08 bytes)
**Status**: ✅ Defined in Ghidra
**Location**: Pointed to by StatList+0x24
**Usage**: Individual stat entry
**Key Fields**: wSubIndex, wStatIndex, dwStatValue
**Reference**: D2_STRUCTURES_REFERENCE.md line 314

---

## Skill Structures

### Info
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0xA8
**Usage**: Unit skill info
**Key Fields**: pGame1C, pFirstSkill, pLeftSkill, pRightSkill
**Reference**: examples/D2Structs.h line 440

### Skill
**Status**: ✅ Defined in Ghidra
**Location**: Linked list from Info
**Usage**: Skill data
**Key Fields**: pSkillInfo, pNextSkill, dwSkillLevel, dwFlags
**Reference**: examples/D2Structs.h line 431

### SkillInfo
**Status**: ✅ Defined in Ghidra
**Location**: Skill+0x00
**Usage**: Skill definition
**Key Fields**: wSkillId
**Reference**: examples/D2Structs.h line 427

---

## Graphics Structures

### GfxCell
**Status**: ✅ Defined in Ghidra
**Location**: Referenced by CellFile
**Usage**: Graphics cell data
**Key Fields**: flags, width, height, xoffs, yoffs, lpParent, length, cols
**Reference**: examples/D2Structs.h line 72

### CellFile
**Status**: ✅ Defined in Ghidra
**Location**: Referenced by CellContext
**Usage**: Cell file container
**Key Fields**: dwVersion, dwFlags, eFormat, termination, numdirs, numcells, cells
**Reference**: examples/D2Structs.h line 96

### CellContext
**Status**: ✅ Defined in Ghidra
**Location**: Animation context
**Usage**: Cell animation context
**Key Fields**: direction, hCell, pCellFile, nCellNo
**Reference**: examples/D2Structs.h line 110

### Light
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0x64
**Usage**: Lighting information
**Key Fields**: dwType, dwStaticValid, pnStaticMap
**Reference**: examples/D2Structs.h line 419

---

## Automap Structures

### AutomapLayer
**Status**: ✅ Defined in Ghidra
**Location**: Automap data
**Usage**: Automap layer container
**Key Fields**: nLayerNo, fSaved, pFloors, pWalls, pObjects, pExtras, pNextLayer
**Reference**: examples/D2Structs.h line 119

### AutomapLayer2
**Status**: ✅ Defined in Ghidra
**Location**: Alternate layer format
**Usage**: Secondary automap layer
**Key Fields**: nLayerNo
**Reference**: examples/D2Structs.h line 129

### AutomapCell
**Status**: ✅ Defined in Ghidra
**Location**: Cell in automap tree
**Usage**: Automap cell BST node
**Key Fields**: fSaved, nCellNo, xPixel, yPixel, wWeight, pLess, pMore
**Reference**: examples/D2Structs.h line 62

---

## UI Structures

### Control
**Status**: ✅ Defined in Ghidra
**Location**: UI control
**Usage**: UI element container
**Key Fields**: dwType, dwPosX/Y, dwSizeX/Y, fnCallback, fnClick, pNext, pFirstText, wText, dwCursorPos, dwIsCloaked
**Reference**: examples/D2Structs.h line 156

### ControlText
**Status**: ✅ Defined in Ghidra
**Location**: Control+0x48
**Usage**: Text in UI control
**Key Fields**: wText, dwColor, pNext
**Reference**: examples/D2Structs.h line 148

### OverheadMsg
**Status**: ✅ Defined in Ghidra
**Location**: UnitAny+0xA4
**Usage**: Overhead message display
**Key Fields**: dwTrigger, Msg[232]
**Reference**: examples/D2Structs.h line 736

---

## Game/Network Structures

### GameStructInfo
**Status**: ✅ Defined in Ghidra
**Location**: Game session data
**Usage**: Current game information
**Key Fields**: szGameName, szGameServerIp, szAccountName, szCharName, szRealmName, szGamePassword
**Reference**: examples/D2Structs.h line 50

### BnetData
**Status**: ✅ Defined in Ghidra
**Location**: Battle.net data
**Usage**: Network session data
**Key Fields**: dwId[4], szGameName, szGameIP, szAccountName, szPlayerName, szRealmName, nCharClass, nDifficulty, szGamePass, szGameDesc
**Reference**: examples/D2Structs.h line 624

### RosterUnit
**Status**: ✅ Defined in Ghidra
**Location**: Party roster
**Usage**: Party member data
**Key Fields**: szName, dwUnitId, dwPartyLife, dwClassId, wLevel, wPartyId, dwLevelId, Xpos, Ypos, dwPartyFlags, pNext
**Reference**: examples/D2Structs.h line 195

### PartyPlayer
**Status**: ✅ Defined in Ghidra
**Location**: Alternative party format
**Usage**: Party player info
**Key Fields**: name2, nUnitId, life, chrtype, chrlvl, partyno, flags
**Reference**: examples/D2Structs.h line 217

---

## Quest Structures

### QuestInfo
**Status**: ✅ Defined in Ghidra
**Location**: PlayerData+0x10/0x14/0x18
**Usage**: Quest progress data
**Key Fields**: pBuffer
**Reference**: examples/D2Structs.h line 234

### Waypoint
**Status**: ✅ Defined in Ghidra
**Location**: PlayerData+0x1C/0x20/0x24
**Usage**: Waypoint activation flags
**Key Fields**: flags
**Reference**: examples/D2Structs.h line 239

---

## Interaction Structures

### InteractStruct
**Status**: ✅ Defined in Ghidra
**Location**: Interaction data
**Usage**: Unit interaction parameters
**Key Fields**: dwMoveType, lpPlayerUnit, lpTargetUnit, dwTargetX, dwTargetY
**Reference**: examples/D2Structs.h line 85

### AttackStruct
**Status**: ✅ Defined in Ghidra
**Location**: Attack data
**Usage**: Combat interaction parameters
**Key Fields**: dwAttackType, lpPlayerUnit, lpTargetUnit, dwTargetX, dwTargetY
**Reference**: examples/D2Structs.h line 691

---

## Text File Structures

### LevelTxt
**Status**: ✅ Defined in Ghidra
**Location**: Level definition lookup
**Usage**: Level.txt data
**Key Fields**: dwLevelNo, szName, szEntranceText, szLevelDesc, wName, wEntranceText, nObjGroup, nObjPrb
**Reference**: examples/D2Structs.h line 134

### MonsterTxt
**Status**: ✅ Defined in Ghidra
**Location**: Monster definition lookup
**Usage**: MonStats.txt data
**Key Fields**: nLocaleTxtNo, flag, velocity, tcs, szDescriptor
**Reference**: examples/D2Structs.h line 493

### ObjectTxt
**Status**: ✅ Defined in Ghidra
**Location**: Object definition lookup
**Usage**: Objects.txt data
**Key Fields**: szName, wszName, nSelectable0, nOrientation, nSubClass, nParm0, nPopulateFn, nOperateFn, nAutoMap
**Reference**: examples/D2Structs.h line 536

---

## Miscellaneous Structures

### TargetInfo
**Status**: ✅ Defined in Ghidra
**Location**: Targeting data
**Usage**: Target selection info
**Key Fields**: pPlayer, xPos, yPos
**Reference**: examples/D2Structs.h line 29

### LevelNameInfo
**Status**: ✅ Defined in Ghidra
**Location**: Level name data
**Usage**: Level identification
**Key Fields**: nX, nY, nLevelId, nAct
**Reference**: examples/D2Structs.h line 35

### InventoryInfo
**Status**: ✅ Defined in Ghidra
**Location**: Inventory layout
**Usage**: Inventory grid definition
**Key Fields**: nLocation, nMaxXCells, nMaxYCells
**Reference**: examples/D2Structs.h line 43

### InventoryLayout
**Status**: ✅ Defined in Ghidra
**Location**: UI inventory layout
**Usage**: Inventory display parameters
**Key Fields**: SlotWidth, SlotHeight, Left, Right, Top, Bottom, SlotPixelWidth, SlotPixelHeight
**Reference**: examples/D2Structs.h line 751

### NPCMenu
**Status**: ✅ Defined in Ghidra
**Location**: NPC interaction
**Usage**: NPC menu data
**Key Fields**: dwNPCClassId, dwEntryAmount, wEntryId[4], dwEntryFunc[4]
**Reference**: examples/D2Structs.h line 721

### ItemStruct_t
**Status**: ✅ Defined in Ghidra
**Location**: Network item packet
**Usage**: Item network transmission
**Key Fields**: MessageID, Action, ItemID, flags (sockets, identified, ethereal, etc.), Location, ItemCode, ItemLevel
**Reference**: examples/D2Structs.h line 1052

---

## Warden/Anti-Cheat Structures

### WardenClient_t
**Status**: ✅ Defined in Ghidra
**Location**: Anti-cheat client
**Usage**: Warden client data
**Key Fields**: pWardenRegion, cbSize, nModuleCount, param, fnSetupWarden
**Reference**: examples/D2Structs.h line 677

### WardenClientRegion_t
**Status**: ✅ Defined in Ghidra
**Location**: Warden memory region
**Usage**: Warden protected region
**Key Fields**: cbAllocSize, offsetFunc1, offsetRelocAddressTable, nRelocCount, offsetWardenSetup, offsetImportAddressTable, nImportDllCount, nSectionCount
**Reference**: examples/D2Structs.h line 657

### WardenIATInfo_t
**Status**: ✅ Defined in Ghidra
**Location**: Warden IAT data
**Usage**: Import table info
**Key Fields**: offsetModuleName, offsetImportTable
**Reference**: examples/D2Structs.h line 685

### SMemBlock_t
**Status**: ✅ Defined in Ghidra
**Location**: Memory block
**Usage**: Allocated memory tracking
**Key Fields**: cbSize, data
**Reference**: examples/D2Structs.h line 670

---

## Data Table Structures

### sgptDataTable
**Status**: ✅ Defined in Ghidra
**Location**: Global data tables
**Usage**: Pointers to all game txt data
**Key Fields**: pPlayerClass, pBodyLocs, pStorePage, pElemTypes (and 40+ more table pointers with record counts)
**Reference**: examples/D2Structs.h line 770

### MpqTable
**Status**: ⚠️ Partially defined
**Location**: MPQ file data
**Usage**: Game archive tables
**Key Fields**: Unknown - placeholder structure
**Reference**: examples/D2Structs.h line 765

---

## Unknown/Future Structures

When documenting functions, if you encounter repeated access patterns that don't match any known structure above, create a new structure definition using the following template:

### [StructureName] (size bytes)
**Status**: 🆕 Newly Discovered
**Location**: [Where it's referenced from]
**Usage**: [What it's used for]
**Key Fields**: [Important fields discovered]
**Reference**: [Function or address where discovered]
**Discovery Date**: [Date]
**Documented By**: [Who found it]

**Evidence**:
- Assembly patterns observed
- Offset access patterns
- Field types inferred from usage
- Cross-references analyzed

---

## Structure Counts

**Total Defined**: 60+ structures
**Fully Documented**: 58 structures ✅
**Partially Documented**: 2 structures ⚠️ (TileData, MpqTable)
**Pending Discovery**: Unknown structures to be found during analysis 🔍

---

## Adding New Structures

When you discover a new structure:

1. **Verify the pattern**: Ensure you see consistent offset access across multiple functions
2. **Document the fields**: Record all observed offsets, sizes, and types
3. **Add to this document**: Use the template above under "Unknown/Future Structures"
4. **Create in Ghidra**: Use `create_struct()` with the field definitions
5. **Update D2_STRUCTURES_REFERENCE.md**: Add complete field layout table
6. **Test application**: Apply to several functions to verify correctness
7. **Update structure count**: Increment total at bottom of this document

---

**Document Status**: Living document - update as new structures are discovered
**Maintenance**: Add new structures immediately upon discovery and verification
**Quality**: All structures should have verified offsets from assembly analysis before being marked ✅

---

**End of Inventory - Last structure added**: 2025-10-24 (Initial import from D2Structs.h)
