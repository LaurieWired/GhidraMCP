# How to Apply UnitAny Struct in Ghidra - Step-by-Step Guide

## Quick Start (5 Minutes)

### Option 1: Copy-Paste into Ghidra Script Console

1. Open Ghidra Script Manager (Tools → Script Manager)
2. Create new Python script named `CreateUnitAnyStruct`
3. Paste the code below
4. Run the script

### Option 2: Manual GUI Method

1. Window → Data Type Manager
2. Create new struct named "UnitAny" with size 0xF4
3. Add 40 fields (see table below)

---

## Complete Field Table

Copy this table and use it to create all fields in Ghidra:

| Offset | Hex | Field Name | Type | Size | Comment |
|--------|-----|-----------|------|------|---------|
| 0 | 0x00 | dwType | dword | 4 | Unit type (0=Player, 1=Monster, 2=Object, 3=Missile, 4=Item, 5=Tile) |
| 4 | 0x04 | dwTxtFileNo | dword | 4 | TXT file record number |
| 8 | 0x08 | _1 | dword | 4 | Reserved |
| 12 | 0x0C | dwUnitId | dword | 4 | Unique unit ID |
| 16 | 0x10 | dwMode | dword | 4 | Unit mode/state |
| 20 | 0x14 | pData | pointer | 4 | Type-specific data (union) |
| 24 | 0x18 | dwAct | dword | 4 | Act index |
| 28 | 0x1C | pAct | pointer | 4 | Act structure pointer |
| 32 | 0x20 | dwSeed_0 | dword | 4 | Random seed part 1 |
| 36 | 0x24 | dwSeed_1 | dword | 4 | Random seed part 2 |
| 40 | 0x28 | _2 | dword | 4 | Reserved |
| 44 | 0x2C | pPath | pointer | 4 | Path structure (movement) |
| 48 | 0x30 | _3_0 | dword | 4 | Reserved |
| 52 | 0x34 | _3_1 | dword | 4 | Reserved |
| 56 | 0x38 | _3_2 | dword | 4 | Reserved |
| 60 | 0x3C | _3_3 | dword | 4 | Reserved |
| 64 | 0x40 | _3_4 | dword | 4 | Reserved |
| 68 | 0x44 | dwGfxFrame | dword | 4 | Graphics frame |
| 72 | 0x48 | dwFrameRemain | dword | 4 | Frames remaining |
| 76 | 0x4C | wFrameRate | word | 2 | Frame rate |
| 78 | 0x4E | _4 | word | 2 | Reserved |
| 80 | 0x50 | pGfxUnk | pointer | 4 | Graphics data |
| 84 | 0x54 | pGfxInfo | pointer | 4 | Graphics info |
| 88 | 0x58 | _5 | dword | 4 | Reserved |
| 92 | 0x5C | pStats | pointer | 4 | Statistics list |
| 96 | 0x60 | pInventory | pointer | 4 | Inventory |
| 100 | 0x64 | ptLight | pointer | 4 | Light structure |
| 104-136 | 0x68-0x88 | _6_0 to _6_8 | dword | 36 | Reserved (9 dwords) |
| 140 | 0x8C | wX | word | 2 | X coordinate |
| 142 | 0x8E | wY | word | 2 | Y coordinate |
| 144 | 0x90 | _7 | dword | 4 | Reserved |
| 148 | 0x94 | dwOwnerType | dword | 4 | Owner type |
| 152 | 0x98 | dwOwnerId | dword | 4 | Owner ID |
| 156-164 | 0x9C-0xA3 | _8_0, _8_1 | dword | 8 | Reserved |
| 164 | 0xA4 | pOMsg | pointer | 4 | Overhead message |
| 168 | 0xA8 | pInfo | pointer | 4 | Skill info |
| 172-196 | 0xAC-0xC3 | _9_0 to _9_5 | dword | 24 | Reserved |
| 196 | 0xC4 | dwFlags | dword | 4 | Unit flags |
| 200 | 0xC8 | dwFlags2 | dword | 4 | Unit flags 2 |
| 204-220 | 0xCC-0xDC | _10_0 to _10_4 | dword | 20 | Reserved |
| 224 | 0xE0 | pChangedNext | pointer | 4 | Next in changed list |
| 228 | 0xE4 | pRoomNext | pointer | 4 | Next in room |
| 232 | 0xE8 | pListNext | pointer | 4 | Next in list (self-ref) |
| 236 | 0xEC | szNameCopy | string[16] | 16 | Name copy |

**Total Size**: 244 bytes (0xF4)

---

## Method 1: Ghidra Script Console (Easiest)

### Step 1: Open Script Manager

1. **Tools** → **Python** (or Script Manager)
2. **File** → **New** → **Python Script**
3. Name: `CreateUnitAnyStruct`

### Step 2: Paste This Code

```python
# Create UnitAny struct in Ghidra
from ghidra.program.model.data import StructureDataType, IntegerDataType, PointerDataType, ArrayDataType, CharDataType

# Create the struct
unitany = StructureDataType("UnitAny", 244)

# Basic identification (0x00-0x10)
unitany.add(IntegerDataType(4), 4, "dwType", "Unit type")
unitany.add(IntegerDataType(4), 4, "dwTxtFileNo", "TXT file number")
unitany.add(IntegerDataType(4), 4, "_1", "Reserved")
unitany.add(IntegerDataType(4), 4, "dwUnitId", "Unit ID")
unitany.add(IntegerDataType(4), 4, "dwMode", "Unit mode")

# Type-specific data (0x14-0x1C)
unitany.add(PointerDataType(), 4, "pData", "Type-specific data")
unitany.add(IntegerDataType(4), 4, "dwAct", "Act index")
unitany.add(PointerDataType(), 4, "pAct", "Act pointer")

# Random seed (0x20-0x28)
unitany.add(IntegerDataType(4), 4, "dwSeed_0", "Seed part 1")
unitany.add(IntegerDataType(4), 4, "dwSeed_1", "Seed part 2")
unitany.add(IntegerDataType(4), 4, "_2", "Reserved")

# Path and reserved (0x2C-0x40)
unitany.add(PointerDataType(), 4, "pPath", "Path pointer")
unitany.add(IntegerDataType(4), 4, "_3_0", "Reserved")
unitany.add(IntegerDataType(4), 4, "_3_1", "Reserved")
unitany.add(IntegerDataType(4), 4, "_3_2", "Reserved")
unitany.add(IntegerDataType(4), 4, "_3_3", "Reserved")
unitany.add(IntegerDataType(4), 4, "_3_4", "Reserved")

# Graphics (0x44-0x58)
unitany.add(IntegerDataType(4), 4, "dwGfxFrame", "Graphics frame")
unitany.add(IntegerDataType(4), 4, "dwFrameRemain", "Frames remaining")
unitany.add(IntegerDataType(2), 2, "wFrameRate", "Frame rate")
unitany.add(IntegerDataType(2), 2, "_4", "Reserved")
unitany.add(PointerDataType(), 4, "pGfxUnk", "Graphics data")
unitany.add(PointerDataType(), 4, "pGfxInfo", "Graphics info")
unitany.add(IntegerDataType(4), 4, "_5", "Reserved")

# Statistics (0x5C-0x64)
unitany.add(PointerDataType(), 4, "pStats", "Statistics list")
unitany.add(PointerDataType(), 4, "pInventory", "Inventory pointer")
unitany.add(PointerDataType(), 4, "ptLight", "Light pointer")

# Reserved array (0x68-0x88)
for i in range(9):
    unitany.add(IntegerDataType(4), 4, f"_6_{i}", "Reserved")

# Position (0x8C-0x90)
unitany.add(IntegerDataType(2), 2, "wX", "X coordinate")
unitany.add(IntegerDataType(2), 2, "wY", "Y coordinate")
unitany.add(IntegerDataType(4), 4, "_7", "Reserved")

# Ownership (0x94-0xA0)
unitany.add(IntegerDataType(4), 4, "dwOwnerType", "Owner type")
unitany.add(IntegerDataType(4), 4, "dwOwnerId", "Owner ID")
unitany.add(IntegerDataType(4), 4, "_8_0", "Reserved")
unitany.add(IntegerDataType(4), 4, "_8_1", "Reserved")

# Messages (0xA4-0xA8)
unitany.add(PointerDataType(), 4, "pOMsg", "Overhead message")
unitany.add(PointerDataType(), 4, "pInfo", "Info pointer")

# Reserved array (0xAC-0xC3)
for i in range(6):
    unitany.add(IntegerDataType(4), 4, f"_9_{i}", "Reserved")

# Flags (0xC4-0xC8)
unitany.add(IntegerDataType(4), 4, "dwFlags", "Unit flags")
unitany.add(IntegerDataType(4), 4, "dwFlags2", "Unit flags 2")

# Reserved array (0xCC-0xDC)
for i in range(5):
    unitany.add(IntegerDataType(4), 4, f"_10_{i}", "Reserved")

# Linked lists (0xE0-0xE8)
unitany.add(PointerDataType(), 4, "pChangedNext", "Changed list next")
unitany.add(PointerDataType(), 4, "pRoomNext", "Room list next")
unitany.add(PointerDataType(), 4, "pListNext", "General list next")

# Name (0xEC-0xFC)
char_array = ArrayDataType(CharDataType(), 16, 1)
unitany.add(char_array, 16, "szNameCopy", "Name copy")

# Add to program
try:
    currentProgram.getDataTypeManager().addDataType(unitany, None)
    print("SUCCESS: UnitAny struct created!")
    print(f"  Size: {unitany.getLength()} bytes")
    print(f"  Fields: {unitany.getNumComponents()}")
except Exception as e:
    print(f"ERROR: {e}")
```

### Step 3: Run the Script

1. **File** → **Run Script**
2. Check the output console for success message

---

## Method 2: Manual GUI Creation

### Step 1: Open Data Type Manager

1. **Window** → **Data Type Manager**

### Step 2: Create New Structure

1. In the left panel, right-click on a category (e.g., "user_defined")
2. **Create Structure**
3. Name: `UnitAny`
4. Size: `244` (0xF4 in decimal)

### Step 3: Add Fields

1. **Edit** → **Add Field**
2. For each row in the field table above:
   - **Name**: Field name (e.g., "dwType")
   - **Type**: Choose type (dword, word, pointer, char[16])
   - **Comment**: Add description

3. Click **OK** for each field

### Step 4: Verify and Save

1. Verify total size is 244 bytes
2. Verify all 40 fields are present
3. **File** → **Save**

---

## Method 3: Using Eclipse/Ghidra Development Environment

If you have the Ghidra source code:

1. Create Java class extending `StructureDataType`
2. Define all fields programmatically
3. Compile and load

(This is more advanced and not necessary for basic use)

---

## Applying the Struct to Functions

Once UnitAny struct is created, apply it to functions:

### For Each Function (Manual Method):

1. **Navigate to function address** (e.g., 0x6fd59276)
2. **Click on function name** in decompiler
3. **Right-click** → **Edit Function Signature**
4. Change: `void *pUnit` → `UnitAny *pUnit`
5. **Click green checkmark** to apply
6. **Verify** in decompiler (should show `pUnit->dwType` not `*(int*)(pUnit+0x00)`)

### Functions to Type (Tier 1 - High Confidence):

```
0x6fd59276  ProcessUnitCoordinatesAndPath(UnitAny *pUnit, int updateFlag)
0x6fd6a520  IsValidUnitType(UnitAny *pUnit)
0x6fd6a610  IsUnitInValidState(UnitAny *pUnit)
0x6fd5dce0  TeleportUnitToCoordinates(UnitAny *pUnit, int x, int y)
0x6fd5dab0  SynchronizeUnitPositionAndRoom(UnitAny *pUnit)
0x6fd62030  InitializeUnitStructure(int, int*, ...)  // wrapper, not direct pUnit
0x6fd62140  FilterAndCollectUnits(UnitAny *base, ..., callback)
0x6fd62330  FindClosestUnitInAreaByDistance(UnitAny *baseUnit, ...)
0x6fd62450  FindUnitInInventoryArray(UnitAny *targetUnit, UnitAny *searchUnit)
0x6fd6a770  FindLinkedUnitInChain(UnitAny *baseUnit, int targetId)
0x6fd62720  ProcessUnitsInBoundingBox(int x, int y, ..., callback, context)
0x6fd5d050  ValidateUnitTypeAndFlags(UnitAny *pUnit)
```

---

## Batch Typing (Advanced)

### Using Ghidra Python Console:

```python
# Batch type functions with UnitAny

functions_to_type = [
    (0x6fd59276, "void ProcessUnitCoordinatesAndPath(UnitAny *pUnit, int updateFlag)"),
    (0x6fd6a520, "BOOL IsValidUnitType(UnitAny *pUnit)"),
    (0x6fd6a610, "BOOL IsUnitInValidState(UnitAny *pUnit)"),
    (0x6fd5dce0, "void TeleportUnitToCoordinates(UnitAny *pUnit, int x, int y)"),
    (0x6fd5dab0, "void SynchronizeUnitPositionAndRoom(UnitAny *pUnit)"),
    (0x6fd62140, "int FilterAndCollectUnits(UnitAny *base, int target, int callback)"),
    (0x6fd62330, "UnitAny* FindClosestUnitInAreaByDistance(UnitAny *base, int x, int y, int dist, int callback)"),
    (0x6fd62450, "BOOL FindUnitInInventoryArray(UnitAny *target, UnitAny *search)"),
    (0x6fd6a770, "int FindLinkedUnitInChain(UnitAny *base, int targetId)"),
    (0x6fd62720, "void ProcessUnitsInBoundingBox(int x1, int y1, int x2, int y2, int callback, int ctx)"),
    (0x6fd5d050, "BOOL ValidateUnitTypeAndFlags(UnitAny *pUnit)"),
]

for address, signature in functions_to_type:
    try:
        func = getFunctionAt(toAddr(address))
        if func:
            func.setPrototypeString(signature)
            print(f"✓ {hex(address)}")
        else:
            print(f"✗ {hex(address)} - not found")
    except Exception as e:
        print(f"✗ {hex(address)} - {e}")
```

---

## Verification Checklist

After typing each function:

- [ ] Function signature shows `UnitAny *pUnit` (or similar)
- [ ] Decompiler shows `pUnit->dwType` instead of `*(int*)(pUnit+0x00)`
- [ ] Decompiler shows `pUnit->wX` instead of `*(short*)(pUnit+0x8C)`
- [ ] All field accesses resolve to struct fields
- [ ] No type errors in decompiler
- [ ] Field access patterns make logical sense

---

## Expected Results

### Before (Original):
```c
void ProcessUnitCoordinatesAndPath(void *pUnit, int updateFlag) {
    uint uVar1;
    int iVar2;

    uVar1 = *(uint *)pUnit;
    if (updateFlag == 0) {
        if (uVar1 == 1) {
            *(uint *)(*(int *)(pUnit + 0x2c) + 0x48) = 5;
            iVar2 = *(int *)(pUnit + 0x8c);
            // ... lots of offset math
        }
    }
}
```

### After (Typed with UnitAny):
```c
void ProcessUnitCoordinatesAndPath(UnitAny *pUnit, int updateFlag) {
    uint uVar1;
    int iVar2;

    uVar1 = pUnit->dwType;
    if (updateFlag == 0) {
        if (uVar1 == 1) {
            pUnit->pPath->dwMode = 5;
            iVar2 = pUnit->wX;
            // ... clean field access
        }
    }
}
```

---

## Troubleshooting

### Issue: "Can't resolve datatype: UnitAny"
**Solution**: Struct hasn't been created yet. Create it first using Method 1 or 2 above.

### Issue: Function signature change not applying
**Solution**:
1. Make sure you're in Decompiler view (not Disassembly)
2. Right-click the function NAME in decompiler, not address
3. Use "Edit Function Signature"

### Issue: "UnitAny" shows as red in decompiler
**Solution**: Struct definition has errors. Verify:
- Total size is exactly 244 bytes
- No overlapping fields
- All offsets are correct

### Issue: Fields show wrong values
**Solution**: Check offsets match the table exactly. Off by 1 error will cascade.

---

## Success Criteria

You'll know it's done correctly when:

✅ UnitAny struct appears in Data Type Manager
✅ Struct size is exactly 244 bytes (0xF4)
✅ All 40 fields are present
✅ Can apply to functions without errors
✅ Decompiler shows named fields (pUnit->dwType)
✅ All applied functions show consistent typing
✅ No type errors reported
✅ Decompilation output is readable

---

## Next Steps

1. Create UnitAny struct (use Method 1 or 2 above)
2. Apply typing to 12+ Tier 1 functions
3. Verify decompiler output looks correct
4. Document results
5. Apply same process to related structs:
   - PlayerData (0x28 bytes)
   - ItemData (0x84 bytes)
   - Inventory (0x2C bytes)
   - StatList (0x3C bytes)

---

## References

- **D2Structs.h**: Original struct definition
- **PUNIT_FUNCTIONS_DOCUMENTATION.md**: Detailed function analysis
- **PUNIT_STRUCT_APPLICATION_LOG.md**: Complete application guide

---

**Estimated Time**: 30-60 minutes for complete application
**Difficulty**: Beginner to Intermediate
**Impact**: Transforms 20+ functions from unreadable to clear
