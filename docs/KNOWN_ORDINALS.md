# Known Ordinals Reference

This document maps frequently-used ordinal imports from Diablo II DLLs to their function names and purposes. Use these mappings when adding inline comments to ordinal function calls.

## Quick Reference Format

When documenting ordinal calls, use this inline comment format:
```c
Ordinal_10342(pUnit)  /* D2Common.GetUnitStat */
```

---

## D2Common.dll Ordinals

| Ordinal | Function Name | Purpose | Parameters |
|---------|--------------|---------|------------|
| 10000 | GetUnitData | Get unit data structure | (pUnit) |
| 10001 | GetUnitRoom | Get room containing unit | (pUnit) |
| 10005 | GetUnitX | Get unit X coordinate | (pUnit) |
| 10006 | GetUnitY | Get unit Y coordinate | (pUnit) |
| 10007 | GetUnitState | Get unit state flags | (pUnit, dwState) |
| 10017 | GetUnitStat | Get stat value from unit | (pUnit, nStatId, nLayer) |
| 10029 | GetLevel | Get level pointer from room | (pRoom) |
| 10042 | GetItemData | Get item data table entry | (nItemCode) |
| 10043 | GetSkillData | Get skill data table entry | (nSkillId) |
| 10072 | GetUnitInventory | Get unit inventory pointer | (pUnit) |
| 10082 | IsDataCompressed | Check if data is compressed | (hData) |
| 10107 | GetPlayerData | Get player-specific data | (pUnit) |
| 10109 | GetMonsterData | Get monster-specific data | (pUnit) |
| 10111 | GetObjectData | Get object-specific data | (pUnit) |
| 10127 | EndDrawing | End drawing operation | () |
| 10130 | GetUnitMode | Get unit animation mode | (pUnit) |
| 10342 | GetUnitStat | Get stat value (alternate) | (pUnit, nStatId) |
| 10469 | GetUnitOwner | Get owner unit pointer | (pUnit) |
| 10539 | GetNextInventoryItem | Iterate inventory items | (pUnit, pItem) |
| 10918 | RandSeed | Generate random number | (pSeed) |
| 10949 | GetAreaId | Get current area/map ID | (dwDefault) |
| 10968 | GetFileHandle | Get file handle for resource | (pUnit, nMapId, bEnable) |

## D2Win.dll Ordinals

| Ordinal | Function Name | Purpose | Parameters |
|---------|--------------|---------|------------|
| 10018 | GetMouseX | Get mouse X position | () |
| 10019 | GetMouseY | Get mouse Y position | () |
| 10021 | DrawText | Draw text to screen | (lpszText, x, y, dwColor, bCenter) |
| 10024 | GetTextWidth | Get text pixel width | (lpszText) |
| 10025 | GetTextHeight | Get text pixel height | (lpszText) |
| 10034 | LoadCellFile | Load DC6/DCC cell file | (lpszPath) |
| 10047 | DrawSprite | Draw sprite at position | (pSprite, x, y) |
| 10117 | GetSystemTime | Get system time | () |
| 10127 | FlushDrawBuffer | Flush pending draw calls | () |
| 10130 | SetDrawClip | Set drawing clip rectangle | (x1, y1, x2, y2) |

## D2Client.dll Ordinals

| Ordinal | Function Name | Purpose | Parameters |
|---------|--------------|---------|------------|
| 10000 | GetPlayerUnit | Get local player unit | () |
| 10004 | GetDifficulty | Get current difficulty | () |
| 10011 | GetMouseItem | Get item under cursor | () |
| 10014 | GetCursorItem | Get cursor-held item | () |
| 10020 | GetUIState | Get UI panel state | (nUIType) |

## D2Gfx.dll Ordinals

| Ordinal | Function Name | Purpose | Parameters |
|---------|--------------|---------|------------|
| 10000 | GetHwnd | Get game window handle | () |
| 10001 | GetScreenWidth | Get screen width | () |
| 10002 | GetScreenHeight | Get screen height | () |
| 10003 | GetWindowMode | Get windowed/fullscreen | () |
| 10007 | DrawLine | Draw line primitive | (x1, y1, x2, y2, dwColor) |
| 10010 | DrawRect | Draw rectangle | (x1, y1, x2, y2, dwColor) |
| 10014 | FlipSurface | Flip back buffer | () |

## D2Lang.dll Ordinals

| Ordinal | Function Name | Purpose | Parameters |
|---------|--------------|---------|------------|
| 10000 | GetLocaleString | Get localized string | (nIndex) |
| 10003 | GetStringById | Get string by table ID | (nTableId, nStringId) |
| 10004 | GetLocaleId | Get current locale | () |

## Fog.dll Ordinals (Memory Management)

| Ordinal | Function Name | Purpose | Parameters |
|---------|--------------|---------|------------|
| 10000 | MemAlloc | Allocate memory | (nSize, lpszFile, nLine, dwFlags) |
| 10001 | MemFree | Free memory | (pMem, lpszFile, nLine, dwFlags) |
| 10002 | MemRealloc | Reallocate memory | (pMem, nSize, lpszFile, nLine) |
| 10019 | GetSystemInfo | Get system configuration | () |
| 10021 | ErrorMsg | Display error message | (lpszMsg, ...) |
| 10024 | LogMessage | Log to debug file | (lpszFormat, ...) |
| 10042 | GetInstallPath | Get game install path | () |
| 10101 | EnterCriticalSection | Enter thread lock | (pLock) |
| 10102 | LeaveCriticalSection | Leave thread lock | (pLock) |

## Storm.dll Ordinals (MPQ/Network)

| Ordinal | Function Name | Purpose | Parameters |
|---------|--------------|---------|------------|
| 251 | SFileOpenArchive | Open MPQ archive | (lpszPath, dwPriority, dwFlags, phArchive) |
| 252 | SFileCloseArchive | Close MPQ archive | (hArchive) |
| 253 | SFileOpenFile | Open file in MPQ | (lpszPath, phFile) |
| 265 | SFileReadFile | Read from MPQ file | (hFile, pBuffer, dwBytes, pdwRead) |
| 266 | SFileCloseFile | Close MPQ file | (hFile) |
| 268 | SFileGetFileSize | Get MPQ file size | (hFile, pdwSizeHigh) |
| 401 | SMemAlloc | Storm memory alloc | (nSize, lpszFile, nLine, dwFlags) |
| 403 | SMemFree | Storm memory free | (pMem, lpszFile, nLine, dwFlags) |

---

## Adding New Ordinals

When you discover a new ordinal's purpose:

1. Add it to the appropriate DLL section above
2. Include: Ordinal number, descriptive function name, brief purpose, parameter list
3. If the ordinal appears frequently, consider pattern-matching similar ordinals

## Common Patterns

- **10xxx range in D2Common**: Usually unit/stat manipulation
- **10xxx range in D2Win**: Drawing and UI operations
- **Low ordinals (251-500) in Storm**: MPQ file operations
- **10xxx range in Fog**: Memory and logging utilities

## Unknown Ordinals

When encountering an unknown ordinal, analyze its behavior:
1. Check parameter count and types
2. Examine return value usage
3. Look at calling context
4. Add descriptive comment based on observed behavior:
   ```c
   Ordinal_12345(pData, nSize)  /* Unknown - appears to validate buffer */
   ```
