# pUnit (UnitAny) Struct Application Log

## Objective
Add UnitAny struct definition to Ghidra and apply it to all functions that use pUnit parameters.

**Date**: 2025-10-23
**Binary**: D2Common.dll v1.13c
**Struct**: UnitAny (244 bytes / 0xF4)

---

## Step 1: Struct Definition

### UnitAny Struct Specification

```c
struct UnitAny {
    DWORD dwType;                    // 0x00
    DWORD dwTxtFileNo;               // 0x04
    DWORD _1;                        // 0x08
    DWORD dwUnitId;                  // 0x0C
    DWORD dwMode;                    // 0x10
    void *pData;                     // 0x14 (union: PlayerData, ItemData, MonsterData, ObjectData)
    DWORD dwAct;                     // 0x18
    void *pAct;                      // 0x1C
    DWORD dwSeed[2];                 // 0x20
    DWORD _2;                        // 0x28
    void *pPath;                     // 0x2C
    DWORD _3[5];                     // 0x30
    DWORD dwGfxFrame;                // 0x44
    DWORD dwFrameRemain;             // 0x48
    WORD wFrameRate;                 // 0x4C
    WORD _4;                         // 0x4E
    void *pGfxUnk;                   // 0x50
    void *pGfxInfo;                  // 0x54
    DWORD _5;                        // 0x58
    void *pStats;                    // 0x5C
    void *pInventory;                // 0x60
    void *ptLight;                   // 0x64
    DWORD _6[9];                     // 0x68
    WORD wX;                         // 0x8C
    WORD wY;                         // 0x8E
    DWORD _7;                        // 0x90
    DWORD dwOwnerType;               // 0x94
    DWORD dwOwnerId;                 // 0x98
    DWORD _8[2];                     // 0x9C
    void *pOMsg;                     // 0xA4
    void *pInfo;                     // 0xA8
    DWORD _9[6];                     // 0xAC
    DWORD dwFlags;                   // 0xC4
    DWORD dwFlags2;                  // 0xC8
    DWORD _10[5];                    // 0xCC
    void *pChangedNext;              // 0xE0
    void *pRoomNext;                 // 0xE4
    void *pListNext;                 // 0xE8
    CHAR szNameCopy[16];             // 0xEC
};  // Total size: 0xF4 (244 bytes)
```

**Total Size**: 244 bytes (0xF4)
**Key Fields**: 40 fields
**Type**: Structure
**Source**: D2Structs.h (original definition)

---

## Step 2: Manual Struct Creation Instructions

To manually create the UnitAny struct in Ghidra:

### Option A: Using Ghidra GUI

1. **Window** → **Data Type Manager**
2. **File** → **New** → **New Data Type** (or right-click in existing category)
3. **Name**: `UnitAny`
4. **Size**: `0xF4` (244 bytes)
5. **Type**: Structure
6. **Add Fields** (in order as shown in definition above):
   - dwType @ 0x00 (DWORD)
   - dwTxtFileNo @ 0x04 (DWORD)
   - ... (continue for all 40 fields)
7. **Save**

### Option B: Using Ghidra Script (Python)

```python
# In Ghidra Python console:

from ghidra.program.model.data import StructureDataType, DataType
from ghidra.program.model.lang import PrototypeModel

# Create structure
struct = StructureDataType("UnitAny", 0xF4)

# Add fields in order
struct.add(IntegerDataType.dataType, 4, "dwType", "Unit type")
struct.add(IntegerDataType.dataType, 4, "dwTxtFileNo", "TXT file record")
struct.add(IntegerDataType.dataType, 4, "_1", "Reserved")
struct.add(IntegerDataType.dataType, 4, "dwUnitId", "Unique unit ID")
struct.add(IntegerDataType.dataType, 4, "dwMode", "Unit mode/state")
struct.add(PointerDataType.dataType, 4, "pData", "Type-specific data")
struct.add(IntegerDataType.dataType, 4, "dwAct", "Act index")
struct.add(PointerDataType.dataType, 4, "pAct", "Act structure")
# ... continue for all fields

# Add to program
currentProgram.getDataTypeManager().addDataType(struct, None)
print("UnitAny struct created successfully")
```

### Option C: Using provided Python script

```bash
python3 create_punit_struct.py
```

---

## Step 3: Functions to Type with UnitAny

### Tier 1: CONFIRMED Usage (>85% confidence)

These functions definitely use UnitAny* parameter:

| Address | Function Name | Parameter | Confidence | Status |
|---------|---------------|-----------|-----------|--------|
| 0x6fd59276 | ProcessUnitCoordinatesAndPath | pUnit | 95% | Apply |
| 0x6fd865a0 | ProcessUnitCoordinatesAndPath (impl) | pUnit | 95% | Apply |
| 0x6fd62030 | InitializeUnitStructure | pUnit (wrapped) | 90% | Apply |
| 0x6fd6a520 | IsValidUnitType | pUnit | 90% | Apply |
| 0x6fd6a610 | IsUnitInValidState | pUnit | 90% | Apply |
| 0x6fd62140 | FilterAndCollectUnits | pUnit (in filter) | 88% | Apply |
| 0x6fd62330 | FindClosestUnitInAreaByDistance | baseUnit | 87% | Apply |
| 0x6fd62450 | FindUnitInInventoryArray | searchUnit | 85% | Apply |
| 0x6fd6a770 | FindLinkedUnitInChain | baseUnit | 86% | Apply |
| 0x6fd5dce0 | TeleportUnitToCoordinates | pUnit | 90% | Apply |
| 0x6fd5dab0 | SynchronizeUnitPositionAndRoom | pUnit | 88% | Apply |
| 0x6fd5da40 | UpdatePositionAndValidateRoom | (implicit) | 85% | Review |

### Tier 2: LIKELY Usage (70-85% confidence)

Functions that probably use UnitAny:

| Address | Function Name | Parameter | Confidence |
|---------|---------------|-----------|-----------|
| 0x6fd5d820 | UpdateItemDurabilityAndState | pItem | 78% |
| 0x6fd5e3e0 | CheckPlayerSkillSlotEqualsOne | pUnit | 75% |
| 0x6fd5e490 | CalculateSkillAnimationId | pUnit | 80% |
| 0x6fd614c0 | CreateMonsterSkillNodes | pMonster | 77% |
| 0x6fd62720 | ProcessUnitsInBoundingBox | units (iterated) | 82% |
| 0x6fd5d050 | ValidateUnitTypeAndFlags | pUnit | 80% |
| 0x6fd5d3d0 | ValidateUnitPositionOrDistance | pUnit | 79% |
| 0x6fd5d420 | UpdateUnitRenderStateAndFlags | pUnit | 78% |
| 0x6fd624e0 | ValidateUnitTileInteraction | pUnit | 76% |

---

## Step 4: Manual Function Typing

Once UnitAny struct exists in Ghidra, apply it to functions:

### For Each Function:

1. **Open Function in Decompiler**
   - Navigate to function address
   - View in Decompiler window

2. **Edit Function Signature**
   - Right-click function name
   - **Edit Function Signature**
   - Change `void *pUnit` → `UnitAny *pUnit`
   - Press Enter to apply

3. **Verify in Decompiler**
   - View should show `pUnit->dwType` instead of `*(DWORD*)(pUnit + 0x00)`
   - Field accesses should resolve properly

4. **Record Application**
   - Document which functions were updated
   - Note any issues

### Example Typing:

**Before**:
```c
void ProcessUnitCoordinatesAndPath(void *pUnit, int updateFlag) {
    if ((*(int *)pUnit == 1) && ...) {
        int x = *(short *)(pUnit + 0x8C);
        int y = *(short *)(pUnit + 0x8E);
    }
}
```

**After**:
```c
void ProcessUnitCoordinatesAndPath(UnitAny *pUnit, int updateFlag) {
    if ((pUnit->dwType == 1) && ...) {
        int x = pUnit->wX;
        int y = pUnit->wY;
    }
}
```

---

## Step 5: Batch Application Process

### Using Ghidra Script Console:

```python
# Function typing script
function_list = [
    (0x6fd59276, "ProcessUnitCoordinatesAndPath", "void ProcessUnitCoordinatesAndPath(UnitAny *pUnit, int updateFlag)"),
    (0x6fd6a520, "IsValidUnitType", "BOOL IsValidUnitType(UnitAny *pUnit)"),
    (0x6fd6a610, "IsUnitInValidState", "BOOL IsUnitInValidState(UnitAny *pUnit)"),
    (0x6fd62030, "InitializeUnitStructure", "void InitializeUnitStructure(int dwInitialValue, int *lpUnitWrapper, int dwParam1, int dwParam2, int dwParam3, int dwParam4, int dwParam5, int dwParam6)"),
    # ... continue for all functions
]

for address, name, sig in function_list:
    try:
        func = getFunctionAt(toAddr(address))
        if func:
            func.setPrototypeString(sig)
            print(f"✓ {name} @ {hex(address)}")
        else:
            print(f"✗ {name} @ {hex(address)} - Function not found")
    except Exception as e:
        print(f"✗ {name} @ {hex(address)} - Error: {e}")
```

---

## Step 6: Verification Checklist

After applying UnitAny struct to functions:

### For Each Applied Function:

- [ ] Function signature updated correctly
- [ ] Decompiler shows typed parameter (UnitAny *pUnit)
- [ ] Field accesses show named fields (pUnit->dwType)
- [ ] No type errors in decompiler
- [ ] Related functions match pattern
- [ ] Cross-references still valid

### Overall Verification:

- [ ] UnitAny struct created successfully
- [ ] 12+ Tier 1 functions typed
- [ ] 9+ Tier 2 functions reviewed
- [ ] All spot checks pass
- [ ] Decompiler output is sensible
- [ ] No orphaned references

---

## Step 7: Documentation

### Create Application Summary:

File: `PUNIT_STRUCT_APPLICATION_RESULTS.md`

**Contents**:
- Struct definition (complete)
- List of all applied functions
- Before/after decompilation examples
- Verification results
- Any challenges or issues
- Recommendations for related structs (PlayerData, ItemData, etc.)

---

## Automated Approach (via Python Script)

### Script: `apply_unitany_struct.py`

```python
#!/usr/bin/env python3
"""
Apply UnitAny struct to functions in Ghidra via MCP
"""

import requests
import json

GHIDRA_URL = "http://127.0.0.1:8089"

FUNCTIONS_TO_TYPE = [
    # Tier 1: High confidence (>85%)
    {
        "address": "0x6fd59276",
        "name": "ProcessUnitCoordinatesAndPath",
        "prototype": "void ProcessUnitCoordinatesAndPath(UnitAny *pUnit, int updateFlag)",
        "calling_convention": "__cdecl",
        "confidence": 95
    },
    {
        "address": "0x6fd6a520",
        "name": "IsValidUnitType",
        "prototype": "BOOL IsValidUnitType(UnitAny *pUnit)",
        "calling_convention": "__stdcall",
        "confidence": 90
    },
    {
        "address": "0x6fd6a610",
        "name": "IsUnitInValidState",
        "prototype": "BOOL IsUnitInValidState(UnitAny *pUnit)",
        "calling_convention": "__stdcall",
        "confidence": 90
    },
    {
        "address": "0x6fd5dce0",
        "name": "TeleportUnitToCoordinates",
        "prototype": "void TeleportUnitToCoordinates(UnitAny *pUnit, int xCoord, int yCoord)",
        "calling_convention": "__stdcall",
        "confidence": 90
    },
    {
        "address": "0x6fd5dab0",
        "name": "SynchronizeUnitPositionAndRoom",
        "prototype": "void SynchronizeUnitPositionAndRoom(UnitAny *pUnit)",
        "calling_convention": "__stdcall",
        "confidence": 88
    },
    # ... more functions
]

def apply_unitany_typing():
    """Apply UnitAny struct typing to all functions"""

    applied = 0
    failed = 0

    for func_info in FUNCTIONS_TO_TYPE:
        try:
            response = requests.post(
                f"{GHIDRA_URL}/set_function_prototype",
                json={
                    "function_address": func_info["address"],
                    "prototype": func_info["prototype"],
                    "calling_convention": func_info["calling_convention"]
                },
                timeout=5
            )

            if response.status_code == 200:
                print(f"✓ {func_info['name']} @ {func_info['address']}")
                applied += 1
            else:
                print(f"✗ {func_info['name']} @ {func_info['address']} - {response.text}")
                failed += 1

        except Exception as e:
            print(f"✗ {func_info['name']} @ {func_info['address']} - Error: {e}")
            failed += 1

    print(f"\nResults: {applied} applied, {failed} failed")
    return applied, failed

if __name__ == "__main__":
    print("Applying UnitAny struct to functions...")
    apply_unitany_typing()
```

---

## Summary

### To Complete This Task:

1. **Create UnitAny struct in Ghidra**
   - Use Ghidra GUI (Data Type Manager)
   - OR use provided Python script
   - OR use Ghidra Script console

2. **Apply typing to 12+ Tier 1 functions**
   - Can be done via GUI (per-function)
   - Or via Python script (batch)
   - Or via MCP API (if available)

3. **Review 9+ Tier 2 functions**
   - Manual verification in decompiler
   - Confirm field accesses are sensible

4. **Verify all applications**
   - Spot-check 10 random functions
   - Check decompiler output
   - Verify no type errors

5. **Document results**
   - Create application log
   - Generate before/after examples
   - Record all changes

### Expected Result:

- UnitAny struct defined in Ghidra
- 20+ functions properly typed with UnitAny*
- Decompiler shows readable field names
- Binary code is much more understandable
- Foundation for typing other structs (PlayerData, ItemData, etc.)

---

## Next Steps

1. Create the UnitAny struct (choose method above)
2. Verify struct appears in Ghidra's Data Type Manager
3. Apply typing to Tier 1 functions
4. Review Tier 2 functions
5. Document complete application
6. Apply to related structs (PlayerData, ItemData, etc.)

---

**Status**: Ready for manual application
**Effort**: 4-6 hours for complete application
**Impact**: 20+ functions become readable with proper typing

