# pUnit Function Index

Complete reference index of all pUnit/UnitAny-related functions organized by category.

## Unit Core Management

### Unit Initialization & Cleanup

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| InitializeUnitStructure | 0x6fd62030 | 0 | Allocates and initializes unit wrapper |
| FinalizeUnitMemory | 0x6fd62000 | 0 | Cleans up and destroys unit |
| SetStructureStateAndConfigurationValues | 0x6fd51000 | 3 | Initializes unit state |

### Unit Type & State Checking

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| IsValidUnitType | 0x6fd6a520 | 0 | Validates unit type and mode |
| IsUnitInValidState | 0x6fd6a610 | 0 | Checks unit usability |
| ValidateUnitTypeAndFlags | 0x6fd5d050 | 0 | Validates type and flag state |
| ValidateUnitMatch | 0x6fd6e880 | 0 | Checks unit ID match |
| CheckUnitStateBits | 0x6fd6a5b0 | 0 | Tests flag bits |
| ValidateUnitNotType4 | 0x6fd6e400 | 0 | Ensures unit is not item |
| ValidatePlayerUnitAndClass | 0x6fd6a660 | 0 | Verifies player and class |

---

## Unit Search & Discovery

### Direct Unit Lookup

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| FindClosestUnitInAreaByDistance | 0x6fd62330 | 0 | Finds nearest unit by distance |
| FindLinkedUnitInChain | 0x6fd6a770 | 0 | Searches unit list by ID |
| FindUnitInInventoryArray | 0x6fd62450 | 0 | Checks if unit in inventory |
| FindItemByTypeAndSubtype | 0x6fd622b0 | 0 | Finds item by type |

### Area & Batch Searches

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| FilterAndCollectUnits | 0x6fd62140 | 0 | Filters and collects units |
| ProcessUnitsInBoundingBox | 0x6fd62720 | 0 | Processes all units in region |
| ProcessPresetUnitsAtCoordinates | 0x6fd5a180 | 2 | Handles preset units at coords |
| CheckNearbyEntitiesAndTriggerActions | 0x6fd5eb80 | 22 | Detects nearby entities |

---

## Position & Movement

### Coordinate Processing

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| ProcessUnitCoordinatesAndPath | 0x6fd59276 | 3 | Updates unit position/path |
| GetRoomAtCoordinates | 0x6fd51330 | 54 | Gets room from coordinates |
| ValidateUnitPositionOrDistance | 0x6fd5d3d0 | 3 | Validates position/distance |
| CalculateAngleBetweenPoints | 0x6fd5d150 | 0 | Calculates angle between points |
| CalculateAngleBetweenTileCoordinates | 0x6fd5d180 | 3 | Angle between tile coords |
| CalculateDirectionAndAngle | 0x6fd5cf40 | 9 | Direction/angle calculation |

### Position Update

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| TeleportUnitToCoordinates | 0x6fd5dce0 | 2 | Teleports unit to position |
| UpdatePositionAndValidateRoom | 0x6fd5da40 | 8 | Updates position and room |
| SynchronizeUnitPositionAndRoom | 0x6fd5dab0 | 2 | Syncs position with room |
| CenterPositionInTileAndUpdate | 0x6fd5db40 | 2 | Centers unit in tile |

### Viewport & Rendering

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| CenterViewportAndResetMovement | 0x6fd5dc80 | 5 | Centers view on unit |
| UpdateViewportToRoomAndCoordinates | 0x6fd5ddc0 | 1 | Updates viewport to position |
| UpdateViewportAndStoreCoordinates | 0x6fd5df30 | 2 | Viewport with coord store |
| UpdateViewportAndSetCursorState | 0x6fd5e150 | 2 | Viewport with cursor update |
| UpdateViewportAndResetCounter | 0x6fd5e1a0 | 2 | Viewport with counter reset |

---

## Inventory & Item Management

### Item Placement

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| PlaceItemIntoInventory | 0x6fd71dd0 | 0 | Places item in inventory |
| PlaceItemIntoBeltSlot | 0x6fd71d70 | 0 | Places item in belt |
| ValidateAndPlaceItemInInventory | 0x6fd71da0 | 0 | Validates and places item |
| PlaceItemInInventory | 0x6fd71e10 | 0 | Adds item to inventory |
| PlaceItemIntoInventoryPage | 0x6fd718a0 | 0 | Places item on page |

### Item Removal

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| RemoveItemFromInventory | 0x6fd71640 | 0 | Removes item from inventory |
| RemoveValidatedItemFromInventory | 0x6fd71b00 | 0 | Removes validated item |

### Item Search & Validation

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| FindItemInInventory | 0x6fd6fe10 | 0 | Finds item in inventory |
| FindMatchingInventoryItem | 0x6fd70270 | 0 | Finds matching item |
| FindInventoryItemByTypeOrSkill | 0x6fd70830 | 0 | Finds by type or skill |
| FindInventoryItemWithStatCheck | 0x6fd70fd0 | 0 | Finds with stat check |
| FindInventoryItemByCriteria | 0x6fd710b0 | 0 | Finds by criteria |
| FindValidSkillItemInInventory | 0x6fd70700 | 0 | Finds valid skill item |
| FindSkillItemInInventory | 0x6fd6ed00 | 0 | Finds skill item |
| FindItemWithSkillByCode | 0x6fd6edf0 | 0 | Finds item by skill code |
| FindItemInInventoryBySkillFlag | 0x6fd6fd40 | 0 | Finds by skill flag |

### Inventory Validation

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| CanPlaceItemInInventory | 0x6fd703b0 | 0 | Checks if item fits |
| ValidateUnitInventoryPointer | 0x6fd724c0 | 0 | Validates inventory pointer |
| CountMatchingInventoryItems | 0x6fd6ec30 | 0 | Counts matching items |

### Inventory Utilities

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| GetInventoryPageItem | 0x6fd6e5b0 | 0 | Gets item from page |
| GetInventoryPageItemByIndex | 0x6fd6e670 | 0 | Gets item by index |
| GetValidatedInventoryPageItem | 0x6fd70010 | 0 | Gets validated page item |
| GetInventoryPageItemData | 0x6fd70490 | 0 | Gets item data from page |
| ClearInventoryItems | 0x6fd71710 | 0 | Clears all items |
| LinkItemToInventorySlot | 0x6fd6f630 | 0 | Links item to slot |
| LinkItemToInventoryList | 0x6fd6f690 | 0 | Links to inventory |
| LinkOrUnlinkItemToInventory | 0x6fd6e4b0 | 0 | Links/unlinks item |
| AddItemToInventoryList | 0x6fd6e4f0 | 0 | Adds to inventory |
| EquipSkillItem | 0x6fd70620 | 0 | Equips skill item |
| ValidateItemOperationAndFindSlot | 0x6fd70db0 | 0 | Validates and finds slot |
| MarkEquippedItemsOnInventoryGrid | 0x6fd70d20 | 0 | Marks equipped items |

### Item Data & Type

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| GetItemDataByTypeValidation | 0x6fd6e3e0 | 0 | Gets item data with validation |
| GetItemDataByTypeAndIndex | 0x6fd68e30 | 0 | Gets item by type/index |
| ValidateItemAndGetUnit | 0x6fd6ff40 | 0 | Validates item and unit |
| GetItemDataStructurePointer | 0x6fd6e790 | 0 | Gets item data pointer |
| GetPlayerItemCode | 0x6fd6e420 | 0 | Gets player item code |

### Socket & Special Items

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| ValidateItemSocketCompatibility | 0x6fd6f980 | 0 | Validates socket compat |
| ValidateItemSocketSkill | 0x6fd72310 | 0 | Validates socket skill |
| ValidateAndInsertItemUnit | 0x6fd717f0 | 0 | Validates and inserts |
| SetupInventoryItem | 0x6fd71790 | 0 | Sets up inventory item |

---

## Statistics & Properties

### Property Queries

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| GetUnitOrItemProperties | 0x6fd6a3d0 | 0 | Gets stats/properties |
| GenerateUnitPropertyByTypeAndIndex | 0x6fd6aa00 | 0 | Generates property |
| GetUnitLocationValue | 0x6fd6b280 | 0 | Gets location value |
| QueryGameDataTable | 0x6fd59306 | 5 | Queries data table |

### Level & Difficulty

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| ValidateAndGetUnitLevel | 0x6fd6e630 | 0 | Gets unit level |
| GetPlayerDifficultyData | 0x6fd6a330 | 0 | Gets difficulty data |
| GetPlayerGameDifficulty | 0x6fd722b0 | 0 | Gets game difficulty |

### Item-Specific Properties

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| GetItemDurabilityValue | 0x6fd721c0 | 0 | Gets item durability |
| UpdateItemDurabilityAndState | 0x6fd5d820 | 7 | Updates durability |
| GetItemProperty | 0x6fd592a6 | 2 | Gets property value |

### Data Table Access

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| GetLevelOrIdentifierFromUnitStructure | 0x6fd51050 | 15 | Gets level from unit |
| GetClassOrQualityFromUnitStructure | 0x6fd51080 | 13 | Gets class/quality |
| GetLevelDataByIndex | 0x6fd51150 | 10 | Gets level data |
| GetSkillDataByIndex | 0x6fd51250 | 7 | Gets skill data |
| GetObjectDataByIndex | 0x6fd512a0 | 4 | Gets object data |
| GetItemTypeDataByIndex | 0x6fd512d0 | 2 | Gets item type data |
| GetSetItemDataByIndex | 0x6fd51300 | 2 | Gets set item data |
| GetObjectTypeDataByIndex | 0x6fd513b0 | 9 | Gets object type data |

---

## Effect & Modification

### Stat Application

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| ApplyObjectStatsToUnit | 0x6fd6b1d0 | 0 | Applies object effects |
| DispatchUnitOperation | 0x6fd592ac | 4 | Dispatches unit operation |
| DispatchIndirectFunction | 0x6fd592f4 | 6 | Dispatches indirect call |
| DispatchSkillGemPropertyEffect | 0x6fd5931e | 12 | Dispatches skill effect |

---

## Skill & Animation

### Skill Animation

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| CalculateSkillAnimationId | 0x6fd5e490 | 88 | Calculates animation ID |
| CreateMonsterSkillNodesWithDirectionMapping | 0x6fd614c0 | 0 | Creates skill nodes |
| ShuffleAndAssignSkillAnimationIds | 0x6fd5e700 | 1 | Shuffles animation IDs |
| InitializeCharacterSkillData | 0x6fd5ec90 | 0 | Initializes skill data |

### Skill Data

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| CheckPlayerSkillSlotEqualsOne | 0x6fd5e3e0 | 1 | Checks skill slot |
| FindInventoryItemWithStatCheck | 0x6fd70fd0 | 0 | Finds item with stats |

---

## Linked List Management

### Unit List Operations

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| RemoveUnitFromLinkedList | 0x6fd6f8f0 | 0 | Removes unit from list |
| RemoveUnitFromPathList | 0x6fd6f720 | 0 | Removes from path list |
| FindNextNullInUnitArray | (varies) | - | Finds null slot in array |

### List Traversal

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| FindAndUpdateNestedStructureByValue | 0x6fd5e430 | 4 | Finds and updates node |

---

## Type-Specific Functions

### Monster Functions

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| GetMonsterModeTableCount | 0x6fd68f70 | 0 | Gets mode table count |
| LoadMonsterModeTable | 0x6fd69330 | 0 | Loads mode table |

### Player Functions

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| LoadAndMergePlayerTables | 0x6fd69650 | 0 | Loads player tables |

### Item Functions

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| FreeUnitMissileData | 0x6fd6d710 | 0 | Frees missile data |
| ITEMSReadInfoFromStreamVersioned | 0x6fd72000 | 0 | Reads item data |
| ReadItemInfoFromStream | 0x6fd72150 | 0 | Reads item info |

---

## Validation & Verification

### General Validation

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| ValidateUnitTileInteraction | 0x6fd624e0 | 0 | Validates tile interaction |
| ValidateCalculateAndValidateMovementDelta | 0x6fd5d0a0 | 1 | Validates movement |
| ValidateLevelStructureMatch | 0x6fd5926a | 4 | Validates level match |
| ValidateDataTableSecondaryIndex | 0x6fd518f0 | 1 | Validates table index |
| ValidateArrayIndex | 0x6fd51280 | 5 | Validates array index |

---

## Collection & Counting

### Count Operations

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| CountMatchingInventoryItems | 0x6fd6ec30 | 0 | Counts matching items |
| CountUniqueItemsInGrid | 0x6fd6f040 | 0 | Counts unique items |

### Collection Operations

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| CollectUniqueInventoryItems | 0x6fd6f1f0 | 0 | Collects unique items |

---

## Advanced Functions

### Room & Collision

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| ValidateAndUpdateRoomAtCoordinates | 0x6fd5d760 | 1 | Updates room context |
| ProcessMovementWithCollisionCheck | 0x6fd5d8e0 | 1 | Movement with collision |
| GetTileObjectTypeFlags | 0x6fd592fa | 7 | Gets tile flags |
| TestObjectTypeFlagBit | 0x6fd51400 | 1 | Tests flag bit |
| TestObjectTypeCoreFlag | 0x6fd51470 | 11 | Tests core flag |

### Data Structure Operations

| Function | Address | XRefs | Description |
|----------|---------|-------|-------------|
| GetStructureByteField | 0x6fd59264 | 6 | Gets struct field |
| GetIndexedWordFromStructure | 0x6fd59270 | 10 | Gets indexed word |
| ProcessUnitCoordinatesAndPath | 0x6fd59276 | 3 | Processes coords/path |

---

## Total Function Count: 100+

**Categories**:
- Unit Management: 10 functions
- Search & Discovery: 8 functions
- Position & Movement: 15 functions
- Inventory & Items: 40 functions
- Statistics & Properties: 15 functions
- Skills & Animation: 4 functions
- Lists & Linking: 3 functions
- Type-Specific: 5 functions

**Most Referenced**:
- GetRoomAtCoordinates: 54 xrefs
- CenterViewportAndResetMovement: 5 xrefs
- CalculateSkillAnimationId: 88 xrefs

---

**Last Updated**: 2025-10-23
**Document Format**: Function Index with Metadata
**Status**: Complete Reference
