# Diablo II Structure Definitions Reference

## Overview

This document provides complete structure definitions for Diablo II reverse engineering. These structures are defined in Ghidra and should be applied during function documentation when their access patterns are detected in the assembly.

**Source**: `examples/D2Structs.h`
**Version**: Diablo II 1.13c
**Last Updated**: 2025-10-24

## Core Structures

### UnitAny Structure

**Size**: 0xEC bytes (236 bytes)
**Description**: Main game entity structure used for all unit types (Player, Monster, Object, Missile, Item, Tile)
**Pointer Types**: `UnitAny*`, `LPUNITANY`

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 4 | dwType | DWORD | Unit type: 0=Player, 1=Monster, 2=Object, 3=Missile, 4=Item, 5=Tile |
| 0x04 | 4 | dwTxtFileNo | DWORD | Index into txt files (MonStats.txt, Skills.txt, etc.) |
| 0x08 | 4 | _1 | DWORD | Unknown/padding |
| 0x0C | 4 | dwUnitId | DWORD | Unique unit identifier |
| 0x10 | 4 | dwMode | DWORD | Current mode/state |
| 0x14 | 4 | pTypeSpecificData | void* | Union pointer to PlayerData/ItemData/MonsterData/ObjectData based on dwType |
| 0x18 | 4 | dwAct | DWORD | Current act number (0-4) |
| 0x1C | 4 | pAct | Act* | Pointer to Act structure |
| 0x20 | 8 | dwSeed[2] | DWORD[2] | Random seed (two DWORDs) |
| 0x28 | 4 | _2 | DWORD | Unknown/padding |
| 0x2C | 4 | pPath | Path* | Union pointer to Path/ItemPath/ObjectPath structure |
| 0x30 | 20 | _3[5] | DWORD[5] | Unknown fields |
| 0x44 | 4 | dwGfxFrame | DWORD | Current graphics animation frame |
| 0x48 | 4 | dwFrameRemain | DWORD | Frames remaining in animation |
| 0x4C | 2 | wFrameRate | WORD | Animation frame rate |
| 0x4E | 2 | _4 | WORD | Unknown/padding |
| 0x50 | 4 | pGfxUnk | BYTE* | Unknown graphics pointer |
| 0x54 | 4 | pGfxInfo | DWORD* | Graphics info pointer |
| 0x58 | 4 | _5 | DWORD | Unknown/padding |
| 0x5C | 4 | pStats | StatList* | Pointer to unit statistics |
| 0x60 | 4 | pInventory | Inventory* | Pointer to inventory |
| 0x64 | 4 | ptLight | Light* | Pointer to lighting info |
| 0x68 | 36 | _6[9] | DWORD[9] | Unknown fields |
| 0x8C | 2 | wX | WORD | X coordinate position |
| 0x8E | 2 | wY | WORD | Y coordinate position |
| 0x90 | 4 | _7 | DWORD | Unknown/padding |
| 0x94 | 4 | dwOwnerType | DWORD | Owner unit type |
| 0x98 | 4 | dwOwnerId | DWORD | Owner unit ID |
| 0x9C | 8 | _8[2] | DWORD[2] | Unknown fields |
| 0xA4 | 4 | pOMsg | OverheadMsg* | Overhead message pointer |
| 0xA8 | 4 | pInfo | Info* | Skill/info pointer |
| 0xAC | 24 | _9[6] | DWORD[6] | Unknown fields |
| 0xC4 | 4 | dwFlags | DWORD | Primary unit flags |
| 0xC8 | 4 | dwFlags2 | DWORD | Secondary unit flags |
| 0xCC | 20 | _10[5] | DWORD[5] | Unknown fields |
| 0xE0 | 4 | pChangedNext | UnitAny* | Next in changed units list |
| 0xE4 | 4 | pRoomNext | UnitAny* | Next unit in room |
| 0xE8 | 4 | pListNext | UnitAny* | Next unit in global list |
| 0xEC | 16 | szNameCopy | char[16] | Name copy buffer |

#### Assembly Recognition Patterns

```asm
; Common UnitAny access patterns
MOV EAX, [EBX+0x00]      ; dwType - unit type check
MOV ECX, [EBX+0x04]      ; dwTxtFileNo - txt file index
MOV EDX, [EBX+0x0C]      ; dwUnitId - unique ID
MOV ESI, [EBX+0x14]      ; pTypeSpecificData - get type-specific pointer
MOV EDI, [EBX+0x2C]      ; pPath - movement data
MOV EAX, [EBX+0x5C]      ; pStats - statistics
MOV ECX, [EBX+0x60]      ; pInventory - items
MOVZX EAX, WORD [EBX+0x8C] ; wX - X coordinate
MOVZX ECX, WORD [EBX+0x8E] ; wY - Y coordinate
TEST DWORD [EBX+0xC4], flags ; dwFlags - flag checks
```

#### Array Notation Mapping

When decompiler shows `param[N]`, calculate byte offset as `N * 4`:

```
param[0]  = +0x00  (dwType)
param[1]  = +0x04  (dwTxtFileNo)
param[3]  = +0x0C  (dwUnitId)
param[4]  = +0x10  (dwMode)
param[5]  = +0x14  (pTypeSpecificData)
param[6]  = +0x18  (dwAct)
param[7]  = +0x1C  (pAct)
param[11] = +0x2C  (pPath)
param[23] = +0x5C  (pStats)
param[24] = +0x60  (pInventory)
param[49] = +0xC4  (dwFlags)
param[50] = +0xC8  (dwFlags2)
```

---

### Path Structure

**Size**: 0x68 bytes (104 bytes)
**Description**: Movement and pathfinding data
**Pointer Types**: `Path*`, also used as `ItemPath*`, `ObjectPath*` via union

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 2 | xOffset | WORD | X offset |
| 0x02 | 2 | xPos | WORD | X position |
| 0x04 | 2 | yOffset | WORD | Y offset |
| 0x06 | 2 | yPos | WORD | Y position |
| 0x08 | 8 | _1[2] | DWORD[2] | Unknown fields |
| 0x10 | 2 | xTarget | WORD | Target X coordinate |
| 0x12 | 2 | yTarget | WORD | Target Y coordinate |
| 0x14 | 8 | _2[2] | DWORD[2] | Unknown fields |
| 0x1C | 4 | pRoom1 | Room1* | Current room |
| 0x20 | 4 | pRoomUnk | Room1* | Unknown room pointer |
| 0x24 | 12 | _3[3] | DWORD[3] | Unknown fields |
| 0x30 | 4 | pUnit | UnitAny* | Owning unit |
| 0x34 | 4 | dwFlags | DWORD | Path flags |
| 0x38 | 4 | _4 | DWORD | Unknown |
| 0x3C | 4 | dwPathType | DWORD | Path type |
| 0x40 | 4 | dwPrevPathType | DWORD | Previous path type |
| 0x44 | 4 | dwUnitSize | DWORD | Unit collision size |
| 0x48 | 16 | _5[4] | DWORD[4] | Unknown fields |
| 0x58 | 4 | pTargetUnit | UnitAny* | Target unit pointer |
| 0x5C | 4 | dwTargetType | DWORD | Target type |
| 0x60 | 4 | dwTargetId | DWORD | Target unit ID |
| 0x64 | 1 | bDirection | BYTE | Movement direction |

#### Assembly Recognition Patterns

```asm
; Access via pUnit->pPath
MOV EAX, [UnitPtr+0x2C]    ; Get pPath pointer
MOVZX ECX, WORD [EAX+0x02] ; xPos
MOV EDX, [EAX+0x1C]        ; pRoom1
MOV ESI, [EAX+0x30]        ; pUnit (back reference)
MOV EDI, [EAX+0x58]        ; pTargetUnit
```

---

### PlayerData Structure

**Size**: 0x28 bytes (40 bytes)
**Description**: Player-specific data (dwType == 0)
**Location**: UnitAny+0x14 (pTypeSpecificData)

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 16 | szName | char[16] | Player character name |
| 0x10 | 4 | pNormalQuest | QuestInfo* | Normal difficulty quests |
| 0x14 | 4 | pNightmareQuest | QuestInfo* | Nightmare difficulty quests |
| 0x18 | 4 | pHellQuest | QuestInfo* | Hell difficulty quests |
| 0x1C | 4 | pNormalWaypoint | Waypoint* | Normal waypoints |
| 0x20 | 4 | pNightmareWaypoint | Waypoint* | Nightmare waypoints |
| 0x24 | 4 | pHellWaypoint | Waypoint* | Hell waypoints |

---

### ItemData Structure

**Size**: 0x88+ bytes (136+ bytes)
**Description**: Item-specific data (dwType == 4)
**Location**: UnitAny+0x14 (pTypeSpecificData)

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 4 | dwQuality | DWORD | Item quality (normal, magic, rare, unique, etc.) |
| 0x04 | 8 | _1[2] | DWORD[2] | Unknown fields |
| 0x0C | 4 | dwItemFlags | DWORD | 1 = owned by player, 0xFFFFFFFF = not owned |
| 0x10 | 8 | _2[2] | DWORD[2] | Unknown fields |
| 0x18 | 4 | dwFlags | DWORD | Item flags |
| 0x1C | 12 | _3[3] | DWORD[3] | Unknown fields |
| 0x28 | 4 | dwQuality2 | DWORD | Quality duplicate/verification |
| 0x2C | 4 | dwItemLevel | DWORD | Item level |
| 0x30 | 8 | _4[2] | DWORD[2] | Unknown fields |
| 0x38 | 2 | wPrefix | WORD | Prefix affix ID |
| 0x3A | 4 | _5[2] | WORD[2] | Unknown fields |
| 0x3E | 2 | wSuffix | WORD | Suffix affix ID |
| 0x40 | 4 | _6 | DWORD | Unknown |
| 0x44 | 1 | BodyLocation | BYTE | Body equipment slot |
| 0x45 | 1 | ItemLocation | BYTE | Non-body location (0xFF if in body/belt) |
| 0x46 | 1 | _7 | BYTE | Unknown |
| 0x47 | 2 | _8 | WORD | Unknown |
| 0x48 | 16 | _9[4] | DWORD[4] | Unknown fields |
| 0x5C | 4 | pOwnerInventory | Inventory* | Owner's inventory |
| 0x60 | 4 | _10 | DWORD | Unknown |
| 0x64 | 4 | pNextInvItem | UnitAny* | Next item in inventory list |
| 0x68 | 1 | _11 | BYTE | Unknown |
| 0x69 | 1 | NodePage | BYTE | Actual location (most reliable) |
| 0x6A | 2 | _12 | WORD | Unknown |
| 0x6C | 24 | _13[6] | DWORD[6] | Unknown fields |
| 0x84 | 4 | pOwner | UnitAny* | Owning unit |

---

### MonsterData Structure

**Size**: 0x60+ bytes (96+ bytes)
**Description**: Monster-specific data (dwType == 1)
**Location**: UnitAny+0x14 (pTypeSpecificData)

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 22 | _1 | BYTE[22] | Unknown fields |
| 0x16 | 1 | fFlags | Bitfield | fUnk:1, fNormal:1, fChamp:1, fBoss:1, fMinion:1 |
| 0x17 | 2 | _2 | WORD | Unknown |
| 0x18 | 4 | _3 | DWORD | Unknown |
| 0x1C | 9 | anEnchants | BYTE[9] | Enchantment IDs array |
| 0x25 | 1 | _4 | BYTE | Unknown |
| 0x26 | 2 | wUniqueNo | WORD | Unique monster number |
| 0x28 | 4 | _5 | DWORD | Unknown |
| 0x2C | 56 | wName | wchar_t[28] | Monster name (wide string) |

---

### MissileData Structure

**Size**: 0x34 bytes (52 bytes)
**Description**: Missile-specific data (dwType == 3)
**Location**: UnitAny+0x14 (pTypeSpecificData)

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 6 | _1 | BYTE[6] | Unknown fields |
| 0x06 | 2 | wClassOrQuality | WORD | Missile class/quality identifier |
| 0x08 | 2 | _2 | WORD | Unknown |
| 0x0A | 2 | _3 | SHORT | Unknown (read by some ordinals) |
| 0x0C | 2 | nSkillLevel | SHORT | Skill level for missile calculations |
| 0x0E | 30 | _4 | BYTE[30] | Unknown fields |
| 0x2C | 4 | dwField_0x2c | DWORD | Unknown DWORD field |
| 0x30 | 4 | _5 | BYTE[4] | Unknown fields |

#### Recognition Pattern

Functions accessing MissileData typically validate `dwType == 3` first:

```c
if (pUnit->dwType == 3) {
    MissileData *pMData = (MissileData*)pUnit->pTypeSpecificData;
    return pMData->nSkillLevel;
}
return 0;
```

---

### Room1 Structure

**Size**: 0x80 bytes (128 bytes)
**Description**: Active dungeon room instance
**Pointer Types**: `Room1*`, `LPROOM1`

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 4 | pRoomsNear | Room1** | Array of pointers to nearby rooms |
| 0x04 | 12 | _1[3] | DWORD[3] | Unknown fields |
| 0x10 | 4 | pRoom2 | Room2* | Associated Room2 structure |
| 0x14 | 12 | _2[3] | DWORD[3] | Unknown fields |
| 0x20 | 4 | Coll | CollMap* | Collision map |
| 0x24 | 4 | dwRoomsNear | DWORD | Count of nearby rooms |
| 0x28 | 36 | _3[9] | DWORD[9] | Unknown fields |
| 0x4C | 4 | dwXStart | DWORD | Room X start position |
| 0x50 | 4 | dwYStart | DWORD | Room Y start position |
| 0x54 | 4 | dwXSize | DWORD | Room X size |
| 0x58 | 4 | dwYSize | DWORD | Room Y size |
| 0x5C | 24 | _4[6] | DWORD[6] | Unknown fields |
| 0x74 | 4 | pUnitFirst | UnitAny* | First unit in room |
| 0x78 | 4 | _5 | DWORD | Unknown |
| 0x7C | 4 | pRoomNext | Room1* | Next room in list |

---

### Room2 Structure

**Size**: 0x60 bytes (96 bytes)
**Description**: Level room template/data
**Pointer Types**: `Room2*`, `LPROOM2`

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 8 | _1[2] | DWORD[2] | Unknown fields |
| 0x08 | 4 | pRoom2Near | Room2** | Array of pointers to nearby Room2s |
| 0x0C | 20 | _2[5] | DWORD[5] | Unknown fields |
| 0x20 | 4 | pType2Info | DWORD* | Type info pointer |
| 0x24 | 4 | pRoom2Next | Room2* | Next Room2 in list |
| 0x28 | 4 | dwRoomFlags | DWORD | Room flags |
| 0x2C | 4 | dwRoomsNear | DWORD | Count of nearby rooms |
| 0x30 | 4 | pRoom1 | Room1* | Associated Room1 instance |
| 0x34 | 4 | dwPosX | DWORD | X position |
| 0x38 | 4 | dwPosY | DWORD | Y position |
| 0x3C | 4 | dwSizeX | DWORD | X size |
| 0x40 | 4 | dwSizeY | DWORD | Y size |
| 0x44 | 4 | _3 | DWORD | Unknown |
| 0x48 | 4 | dwPresetType | DWORD | Preset type |
| 0x4C | 4 | pRoomTiles | RoomTile* | Room tiles |
| 0x50 | 8 | _4[2] | DWORD[2] | Unknown fields |
| 0x58 | 4 | pLevel | Level* | Parent level |
| 0x5C | 4 | pPreset | PresetUnit* | Preset units in room |

---

### Level Structure

**Size**: 0x1D4 bytes (468 bytes)
**Description**: Act level data
**Pointer Types**: `Level*`, `LPLEVEL`

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 16 | _1[4] | DWORD[4] | Unknown fields |
| 0x10 | 4 | pRoom2First | Room2* | First Room2 in level |
| 0x14 | 8 | _2[2] | DWORD[2] | Unknown fields |
| 0x1C | 4 | dwPosX | DWORD | Level X position |
| 0x20 | 4 | dwPosY | DWORD | Level Y position |
| 0x24 | 4 | dwSizeX | DWORD | Level X size |
| 0x28 | 4 | dwSizeY | DWORD | Level Y size |
| 0x2C | 384 | _3[96] | DWORD[96] | Unknown fields |
| 0x1AC | 4 | pNextLevel | Level* | Next level in list |
| 0x1B0 | 4 | _4 | DWORD | Unknown |
| 0x1B4 | 4 | pMisc | ActMisc* | Act misc data |
| 0x1B8 | 12 | _5[3] | DWORD[3] | Unknown fields |
| 0x1C4 | 8 | dwSeed[2] | DWORD[2] | Level seed (two DWORDs) |
| 0x1CC | 4 | _6 | DWORD | Unknown |
| 0x1D0 | 4 | dwLevelNo | DWORD | Level number/ID |

---

### StatList Structure

**Size**: 0x40 bytes (64 bytes)
**Description**: Linked list of unit statistics

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 36 | _1[9] | DWORD[9] | Unknown fields |
| 0x24 | 4 | pStat | Stat* | Pointer to stats array |
| 0x28 | 2 | wStatCount1 | WORD | Stat count (primary) |
| 0x2A | 2 | wStatCount2 | WORD | Stat count (secondary) |
| 0x2C | 8 | _2[2] | DWORD[2] | Unknown fields |
| 0x34 | 4 | _3 | BYTE* | Unknown pointer |
| 0x38 | 4 | _4 | DWORD | Unknown |
| 0x3C | 4 | pNext | StatList* | Next StatList in chain |

---

### Stat Structure

**Size**: 0x08 bytes (8 bytes)
**Description**: Individual stat entry

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 2 | wSubIndex | WORD | Stat sub-index |
| 0x02 | 2 | wStatIndex | WORD | Stat type ID |
| 0x04 | 4 | dwStatValue | DWORD | Stat value |

---

### Inventory Structure

**Size**: 0x2C bytes (44 bytes)
**Description**: Unit inventory container

#### Field Layout

| Offset | Size | Field Name | Type | Description |
|--------|------|------------|------|-------------|
| 0x00 | 4 | dwSignature | DWORD | Inventory signature/ID |
| 0x04 | 4 | bGame1C | BYTE* | Game data pointer |
| 0x08 | 4 | pOwner | UnitAny* | Owner unit |
| 0x0C | 4 | pFirstItem | UnitAny* | First item in inventory |
| 0x10 | 4 | pLastItem | UnitAny* | Last item in inventory |
| 0x14 | 8 | _1[2] | DWORD[2] | Unknown fields |
| 0x1C | 4 | dwLeftItemUid | DWORD | Left hand item UID |
| 0x20 | 4 | pCursorItem | UnitAny* | Item on cursor |
| 0x24 | 4 | dwOwnerId | DWORD | Owner unit ID |
| 0x28 | 4 | dwItemCount | DWORD | Total item count |

---

## Hungarian Notation Standards

Use these prefixes consistently when naming structure fields and variables:

| Prefix | Type | Examples |
|--------|------|----------|
| dw | DWORD (32-bit) | dwType, dwUnitId, dwFlags, dwTxtFileNo |
| p, lp | Pointer | pNext, lpPlayerUnit, pPath, pTypeSpecificData |
| w | WORD (16-bit) | wLevel, wStatIndex, wClassOrQuality, wX, wY |
| n | Count/number | nCount, nMaxXCells, nSkillLevel |
| sz | Null-terminated string | szName, szGameName |
| f, b | Boolean/flag | fSaved, bActive, bSetFlag |
| an | Array | anEnchants |

---

## Structure Application Guidelines

### 1. Identify Structure Access Patterns

Look for consistent offset patterns in assembly:

```asm
; UnitAny pattern
[EBX+0x00]  ; dwType check
[EBX+0x04]  ; dwTxtFileNo
[EBX+0x14]  ; pTypeSpecificData
[EBX+0x2C]  ; pPath
[EBX+0xC4]  ; dwFlags

; Type-specific data pattern (after dwType validation)
CMP DWORD [EBX+0x00], 3    ; Check if dwType == 3 (missile)
MOV EAX, [EBX+0x14]        ; Get pTypeSpecificData
MOVZX ECX, WORD [EAX+0x0C] ; Access MissileData->nSkillLevel
```

### 2. Apply Structure Types

When you identify structure access:

1. Use `set_local_variable_type` to apply the structure type to parameters
2. Use correct pointer types: `UnitAny*`, `Path*`, `StatList*`, etc.
3. Follow Hungarian notation for all renamed variables

### 3. Type-Specific Data Handling

After detecting `dwType` validation:

- `dwType == 0` → Cast `pTypeSpecificData` to `PlayerData*`
- `dwType == 1` → Cast `pTypeSpecificData` to `MonsterData*`
- `dwType == 2` → Cast `pTypeSpecificData` to `ObjectData*`
- `dwType == 3` → Cast `pTypeSpecificData` to `MissileData*`
- `dwType == 4` → Cast `pTypeSpecificData` to `ItemData*`
- `dwType == 5` → Cast `pTypeSpecificData` to `TileData*`

### 4. Linked Structures

When you see pointer dereferences:

- `pUnit->pPath` → Apply `Path*` type
- `pUnit->pStats` → Apply `StatList*` type
- `pUnit->pInventory` → Apply `Inventory*` type
- `pRoom1->pRoom2` → Apply `Room2*` type
- `pRoom2->pLevel` → Apply `Level*` type

---

## Quick Reference - Common Offsets

### UnitAny Key Fields
```
+0x00  dwType           (unit type 0-5)
+0x04  dwTxtFileNo      (txt file index)
+0x0C  dwUnitId         (unique ID)
+0x10  dwMode           (current mode)
+0x14  pTypeSpecificData (type data pointer)
+0x2C  pPath            (movement data)
+0x5C  pStats           (statistics)
+0x60  pInventory       (items)
+0x8C  wX               (X position WORD)
+0x8E  wY               (Y position WORD)
+0xC4  dwFlags          (primary flags)
```

### Path Key Fields
```
+0x02  xPos             (X position WORD)
+0x06  yPos             (Y position WORD)
+0x1C  pRoom1           (current room)
+0x30  pUnit            (owning unit)
+0x58  pTargetUnit      (target unit)
```

### ItemData Key Fields
```
+0x00  dwQuality        (item quality)
+0x0C  dwItemFlags      (item flags)
+0x38  wPrefix          (prefix affix WORD)
+0x3E  wSuffix          (suffix affix WORD)
+0x44  BodyLocation     (equipment slot BYTE)
+0x84  pOwner           (owner unit)
```

---

**End of Reference Document**
