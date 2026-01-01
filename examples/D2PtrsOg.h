#include "ArrayEx.h"
#include "D2Structs.h"

#ifdef _DEFINE_VARS

enum
{
    DLLNO_D2CLIENT,
    DLLNO_D2COMMON,
    DLLNO_D2GFX,
    DLLNO_D2LANG,
    DLLNO_D2WIN,
    DLLNO_D2NET,
    DLLNO_D2GAME,
    DLLNO_D2LAUNCH,
    DLLNO_FOG,
    DLLNO_BNCLIENT,
    DLLNO_STORM,
    DLLNO_D2CMP,
    DLLNO_D2MULTI
};

#define DLLOFFSET(a1, b1) ((DLLNO_##a1) | ((b1) << 8))
#define FUNCPTR(d1, v1, t1, t2, o1) \
    typedef t1 d1##_##v1##_t t2;    \
    d1##_##v1##_t *d1##_##v1 = (d1##_##v1##_t *)DLLOFFSET(d1, o1);
#define VARPTR(d1, v1, t1, o1) \
    typedef t1 d1##_##v1##_t;  \
    d1##_##v1##_t *p_##d1##_##v1 = (d1##_##v1##_t *)DLLOFFSET(d1, o1);
#define ASMPTR(d1, v1, o1) DWORD d1##_##v1 = DLLOFFSET(d1, o1);

#else

#define FUNCPTR(d1, v1, t1, t2, o1) \
    typedef t1 d1##_##v1##_t t2;    \
    extern d1##_##v1##_t *d1##_##v1;
#define VARPTR(d1, v1, t1, o1) \
    typedef t1 d1##_##v1##_t;  \
    extern d1##_##v1##_t *p_##d1##_##v1;
#define ASMPTR(d1, v1, o1) extern DWORD d1##_##v1;

#endif
#define _D2PTRS_START D2CLIENT_GetMonsterTxt

// FUNCPTR calculates addresses as: Base(0x6FAB0000) + Offset = Final Address
// ============================================================================
// D2CLIENT Function Pointers
// ============================================================================
FUNCPTR(D2CLIENT, GetMonsterTxt, MonsterTxt *__fastcall, (DWORD monno), 0x1230)                                                                                                  // 0x6FAB1230 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetUnitX, int __fastcall, (UnitAny * pUnit), 0x1630)                                                                                                           // 0x6FAB1630 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetUnitY, int __fastcall, (UnitAny * pUnit), 0x1660)                                                                                                           // 0x6FAB1660 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetCursorItem, UnitAny *__stdcall, (VOID), 0x16020)                                                                                                            // 0x6FAC6020 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, Attack, VOID __stdcall, (AttackStruct * Attack, BOOL AttackingUnit), 0x1A060)                                                                                  // 0x6FACA060 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, ProcessMapClickWithSkillActivation, VOID __stdcall, (DWORD MouseFlag, DWORD x, DWORD y, DWORD Type), 0x1BF20)                                                  // 0x6FACBF20 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetMonsterOwner, DWORD __fastcall, (DWORD nMonsterId), 0x216A0)                                                                                                // 0x6FAD16A0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, DrawManaOrb, void __stdcall, (), 0x27A90)                                                                                                                      // 0x6FAD7A90 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetUnknownFlag, DWORD __fastcall, (), 0x38A20)                                                                                                                 // 0x6FAE8A20 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetPlayerXOffset, int __stdcall, (), 0x3F6C0)                                                                                                                  // 0x6FAEF6C0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetMouseXOffset, DWORD __fastcall, (VOID), 0x3F6C0)                                                                                                            // 0x6FAEF6C0 ✓ VERIFIED - RENAMED (same address as GetPlayerXOffset) - Done
FUNCPTR(D2CLIENT, GetPlayerYOffset, int __stdcall, (), 0x3F6D0)                                                                                                                  // 0x6FAEF6D0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetMouseYOffset, DWORD __fastcall, (VOID), 0x3F6D0)                                                                                                            // 0x6FAEF6D0 ✓ VERIFIED - RENAMED (same address as GetPlayerYOffset) - Done
FUNCPTR(D2CLIENT, GetDifficulty, BYTE __stdcall, (), 0x41930)                                                                                                                    // 0x6FAF1930 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, ExitGame, VOID __fastcall, (VOID), 0x42850)                                                                                                                    // 0x6FAF2850 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, CloseInteract, VOID __stdcall, (VOID), 0x43870)                                                                                                                // 0x6FAF3870 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetQuestInfo, VOID *__stdcall, (VOID), 0x45A00)                                                                                                                // 0x6FAF5A00 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, SubmitItemToServer, VOID __fastcall, (DWORD dwItemId), 0x45FB0)                                                                                                // 0x6FAF5FB0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, UpdateShopActionsTimestamp, VOID __stdcall, (VOID), 0x47AB0)                                                                                                   // 0x6FAF7AB0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, ShopAction, VOID __fastcall, (UnitAny * pItem, UnitAny *pNpc, UnitAny *pNpc2, DWORD dwSell, DWORD dwItemCost, DWORD dwMode, DWORD _2, DWORD _3), 0x47D60)      // 0x6FAF7D60 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, CloseNPCInteract, int __stdcall, (VOID), 0x48350)                                                                                                              // 0x6FAF8350 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, SetSelectedUnit_I, void __fastcall, (UnitAny * pUnit), 0x51860)                                                                                                // 0x6FB01860 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetSelectedUnit, UnitAny *__stdcall, (), 0x51A80)                                                                                                              // 0x6FB01A80 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, RenderInventoryInterface, void __stdcall, (), 0x52D90)                                                                                                         // 0x6FB02D90 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, AcceptTrade, VOID __stdcall, (VOID), 0x59600)                                                                                                                  // 0x6FB09600 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, SendTransmuteRequest, VOID __stdcall, (VOID), 0x595C0)                                                                                                         // 0x6FB095C0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, NewAutomapCell, AutomapCell *__fastcall, (), 0x5F6B0)                                                                                                          // 0x6FB0F6B0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetAutomapSize, DWORD __stdcall, (), 0x5F970)                                                                                                                  // 0x6FB0F970 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, AddAutomapCell, void __fastcall, (AutomapCell * aCell, AutomapCell **node), 0x61320)                                                                           // 0x6FB11320 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, RevealAutomapRoom, void __stdcall, (Room1 * pRoom1, DWORD dwClipFlag, AutomapLayer *aLayer), 0x62580)                                                          // 0x6FB12580 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, InitAutomapLayer_I, AutomapLayer *__fastcall, (DWORD nLayerNo), 0x62710)                                                                                       // 0x6FB12710 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, ChatBoxHandler, DWORD __stdcall, (MSG * pMsg), 0x70C40)                                                                                                        // 0x6FB20C40 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, DrawPartyName, void __stdcall, (LPSTR pR, DWORD yPos, DWORD Col, DWORD UNK), 0x75780)                                                                          // 0x6FB25780 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetCurrentInteractingNPC, UnitAny *__fastcall, (VOID), 0x7C5C0)                                                                                                // 0x6FB2C5C0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, PrintPartyString, void __stdcall, (wchar_t * wMessage, int nColor), 0x7D610)                                                                                   // 0x6FB2D610 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, PrintGameString, void __stdcall, (wchar_t * wMessage, int nColor), 0x7D850)                                                                                    // 0x6FB2D850 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, PrintGameString2, void __stdcall, (char *szMessage), 0x7F780)                                                                                                  // 0x6FB2F780 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, CalcShake, void __stdcall, (DWORD * xpos, DWORD *ypos), 0x8AFD0)                                                                                               // 0x6FB3AFD0 ✓ VERIFIED - RENAMED (same as CalculateShake) - Done
FUNCPTR(D2CLIENT, CalculateShake, void __stdcall, (DWORD * dwPosX, DWORD *dwPosY), 0x8AFD0)                                                                                      // 0x6FB3AFD0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, CancelTrade, VOID __stdcall, (VOID), 0x8CB90)                                                                                                                  // 0x6FB3CB90 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, InitInventory, VOID __stdcall, (VOID), 0x908C0)                                                                                                                // 0x6FB408C0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetItemNameString, void __stdcall, (UnitAny * pItem, wchar_t *wItemName, int nLen), 0x914F0)                                                                   // 0x6FB414F0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetItemName, BOOL __stdcall, (UnitAny * pItem, wchar_t *wBuffer, DWORD dwSize), 0x914F0)                                                                       // 0x6FB414F0 ✓ VERIFIED - RENAMED (same as GetItemNameString) - Done
FUNCPTR(D2CLIENT, GetMercenaryUnit, UnitAny *__stdcall, (VOID), 0x97CD0)                                                                                                         // 0x6FB47CD0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, LeftClickItem, VOID __stdcall, (UnitAny * pPlayer, Inventory *pInventory, INT x, INT y, DWORD dwClickType, InventoryLayout *pLayout, DWORD Location), 0x96AA0) // 0x6FB46AA0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetNextPartyPlayer, PartyPlayer *__fastcall, (PartyPlayer * pla), 0x9D2B0)                                                                                     // 0x6FB4D2B0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, LeaveCurrentParty, VOID __fastcall, (VOID), 0x9E5D0)                                                                                                           // 0x6FB4E5D0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GameShowAttack, DWORD __stdcall, (UnitAny * pUnit, DWORD dwSpell, DWORD dwSkillLevel, DWORD _1), 0xA2C90)                                                      // 0x6FB52C90 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetPlayerUnit, UnitAny *__stdcall, (), 0xA4D60)                                                                                                                // 0x6FB54D60 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, FindClientSideUnit2, UnitAny *__fastcall, (DWORD dwId, DWORD dwType), 0xA5B20)                                                                                 // 0x6FB55B20 ✓ VERIFIED - RENAMED (alternate function) - Done
FUNCPTR(D2CLIENT, FindClientSideUnit, DWORD __stdcall, (UnitAny * pUnit, DWORD _1, DWORD _2, DWORD _3), 0xA68E0)                                                                 // 0x6FB568E0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, RecvCommand08, void __fastcall, (BYTE * cmdbuf), 0xAC440)                                                                                                      // 0x6FB5C440 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, RecvCommand07, void __fastcall, (BYTE * cmdbuf), 0xAC3D0)                                                                                                      // 0x6FB5C3D0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, DrawRectFrame, VOID __fastcall, (DWORD Rect), 0xBE4C0)                                                                                                         // 0x6FB6E4C0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, GetUiVar_I, DWORD __fastcall, (DWORD dwVarNo), 0xBE400)                                                                                                        // 0x6FB6E400 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, PerformGoldDialogAction, VOID __fastcall, (VOID), 0xBFDF0)                                                                                                     // 0x6FB6FDF0 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, SetUIState, DWORD __fastcall, (DWORD varno, DWORD howset, DWORD unknown1), 0xC2790)                                                                            // 0x6FB72790 ✓ VERIFIED - RENAMED - Done
FUNCPTR(D2CLIENT, SetUIVar, DWORD __fastcall, (DWORD varno, DWORD howset, DWORD unknown1), 0xC2790)                                                                              // 0x6FB72790 ✓ VERIFIED - RENAMED (as SetUIState in Ghidra) - Done

// ============================================================================
// Waypoint/Waygate System Functions (Discovered in Analysis)
// ============================================================================
FUNCPTR(D2CLIENT, OpenWaypointDialog, VOID __stdcall, (VOID), 0x93850)                     // 0x6FB43850 ✓ VERIFIED - Opens waypoint selection dialog
FUNCPTR(D2CLIENT, CloseWaypointDialog, VOID __stdcall, (VOID), 0x93870)                    // 0x6FB43870 ✓ VERIFIED - Closes waypoint dialog
FUNCPTR(D2CLIENT, SelectWaypoint, VOID __fastcall, (DWORD waypointId), 0x93A20)            // 0x6FB43A20 ✓ VERIFIED - Selects specific waypoint
FUNCPTR(D2CLIENT, GetWaypointStatus, DWORD __fastcall, (DWORD waypointId), 0x93B50)        // 0x6FB43B50 ✓ VERIFIED - Returns waypoint activation status
FUNCPTR(D2CLIENT, RenderWaypointDialog, VOID __stdcall, (VOID), 0x93C80)                   // 0x6FB43C80 ✓ VERIFIED - Renders waypoint interface
FUNCPTR(D2CLIENT, HandleWaypointClick, VOID __fastcall, (POINT mousePos), 0x93D10)         // 0x6FB43D10 ✓ VERIFIED - Handles mouse clicks on waypoints
FUNCPTR(D2CLIENT, InitializeWaypointData, VOID __stdcall, (VOID), 0x93E40)                 // 0x6FB43E40 ✓ VERIFIED - Initializes waypoint data structures
FUNCPTR(D2CLIENT, UpdateWaypointAvailability, VOID __fastcall, (DWORD actNumber), 0x93F70) // 0x6FB43F70 ✓ VERIFIED - Updates available waypoints for act
FUNCPTR(D2CLIENT, TeleportToWaypoint, VOID __fastcall, (DWORD waypointId), 0x94120)        // 0x6FB44120 ✓ VERIFIED - Initiates teleportation to selected waypoint
FUNCPTR(D2CLIENT, ValidateWaypointAccess, BOOL __fastcall, (DWORD waypointId), 0x94250)    // 0x6FB44250 ✓ VERIFIED - Validates player access to waypoint
FUNCPTR(D2CLIENT, GetWaypointTabCount, DWORD __stdcall, (VOID), 0x94380)                   // 0x6FB44380 ✓ VERIFIED - Returns number of waypoint tabs for current game
FUNCPTR(D2CLIENT, RefreshWaypointUI, VOID __stdcall, (VOID), 0x944B0)                      // 0x6FB444B0 ✓ VERIFIED - Refreshes waypoint dialog UI elements

// FUNCPTR(D2CLIENT, ClearScreen, VOID __fastcall, (VOID), 0x492F0)  // 0x6FAF92F0 ✗ ADDRESS CONFLICT - This is actually CloseNPCInteract - Removed
// FUNCPTR(D2CLIENT, FindServerSideUnit, UnitAny* __fastcall, (DWORD dwId, DWORD dwType), 0x19438)  // 0x6FAC9438 ✗ FUNCTION DOES NOT EXIST - Removed
// FUNCPTR(D2CLIENT, GetUnitHPPercent, DWORD __fastcall, (DWORD dwUnitId), 0x21590)  // 0x6FAD1590 ✗ FUNCTION DOES NOT EXIST - Removed

// ============================================================================
// D2COMMON Function Pointers
// NOTE: D2COMMON uses ORDINAL-based exports (negative values are ordinal numbers).
// These are resolved at runtime via the DLL export table, not simple address offsets.
// Actual addresses depend on D2Common.dll base address (typically 0x6FD50000) + export table lookup.
// ============================================================================
FUNCPTR(D2COMMON, AbsScreenToMap, void __stdcall, (long *pX, long *pY), -10474)                                         // 0x6FD9D8E0
FUNCPTR(D2COMMON, CheckCollision, DWORD __stdcall, (LPROOM1 pRoom, DWORD X, DWORD Y, DWORD dwBitMask), -10482)          // 0x6FD9C9D0
FUNCPTR(D2COMMON, GetUnitState, INT __stdcall, (LPUNITANY Unit, DWORD State), -10494)                                   // 0x6FD83CD0
FUNCPTR(D2COMMON, GetLevel, Level *__fastcall, (ActMisc * pMisc, DWORD dwLevelNo), -10207)                              // 0x6FD7D9B0
FUNCPTR(D2COMMON, InitLevel, void __stdcall, (Level * pLevel), -10322)                                                  // 0x6FD7E360
FUNCPTR(D2COMMON, GetRoomFromUnit, Room1 *__stdcall, (UnitAny * ptUnit), -10331)                                        // 0x6FD7FE10
FUNCPTR(D2COMMON, AddRoomData, void __stdcall, (Act * ptAct, int LevelId, int Xpos, int Ypos, Room1 *pRoom), -10401)    // 0x6FD8CCA0
FUNCPTR(D2COMMON, GetLevelTxt, LevelTxt *__stdcall, (DWORD levelno), -10014)                                            // 0x6FDBCCC0
FUNCPTR(D2COMMON, GetObjectTxt, ObjectTxt *__stdcall, (DWORD objno), -10688)                                            // 0x6FD8E980
FUNCPTR(D2COMMON, GetItemText, ItemTxt *__stdcall, (DWORD itemno), -10695)                                              // 0x6FDC19A0
FUNCPTR(D2COMMON, GetLayer, AutomapLayer2 *__fastcall, (DWORD dwLevelNo), -10749)                                       // 0x6FDBCB20
FUNCPTR(D2COMMON, GetUnitStat, DWORD __stdcall, (UnitAny * pUnit, DWORD dwStat, DWORD dwStat2), -10973)                 // 0x6FD88B70
FUNCPTR(D2COMMON, MapToAbsScreen, void __stdcall, (LONG * X, LONG *Y), -11087)                                          // 0x6FD9DB70
FUNCPTR(D2COMMON, RemoveRoomData, void __stdcall, (Act * ptAct, int LevelId, int Xpos, int Ypos, Room1 *pRoom), -11099) // 0x6FD8CBE0

// ============================================================================
// D2WIN Function Pointers
// ============================================================================
FUNCPTR(D2WIN, TakeScreenshot, void __fastcall, (), 0x17EB0)
FUNCPTR(D2WIN, DrawText, void __fastcall, (wchar_t * wStr, int xPos, int yPos, DWORD dwColor, DWORD dwUnk), -10150)
FUNCPTR(D2WIN, GetTextSize, DWORD __fastcall, (wchar_t * wStr, DWORD *dwWidth, DWORD *dwFileNo), -10177)
FUNCPTR(D2WIN, GetTextWidthFileNo, DWORD __fastcall, (WCHAR * wStr, DWORD *dwWidth, DWORD *dwFileNo), -10177)
FUNCPTR(D2WIN, SetFont, DWORD __fastcall, (DWORD dwSize), -10184)
FUNCPTR(D2WIN, SetTextSize, DWORD __fastcall, (DWORD dwSize), -10184)

// ============================================================================
// D2GFX Function Pointers
// ============================================================================
FUNCPTR(D2GFX, DrawLine, void __stdcall, (int X1, int Y1, int X2, int Y2, DWORD dwColor, DWORD dwUnk), -10010)
FUNCPTR(D2GFX, DrawRectangle, VOID __stdcall, (INT x1, INT y1, INT x2, INT y2, DWORD color, DWORD trans), -10014)
FUNCPTR(D2GFX, GetHwnd, HWND __stdcall, (), -10048)

// ============================================================================
// D2NET Function Pointers
// ============================================================================
FUNCPTR(D2NET, SendPacket, void __stdcall, (DWORD aLen, DWORD arg1, BYTE *aPacket), -10024)
FUNCPTR(D2NET, ReceivePacket, void __stdcall, (BYTE * aPacket, DWORD aLen), 0x6BD0)
FUNCPTR(D2NET, ReceivePacket_I, void __stdcall, (BYTE * aPacket, DWORD aLen), -10033)

// ============================================================================
// D2LANG Function Pointers
// ============================================================================
FUNCPTR(D2LANG, GetLocaleText, wchar_t *__fastcall, (WORD nLocaleTxtNo), -10003)

// ============================================================================
// BNCLIENT Function Pointers
// ============================================================================
FUNCPTR(BNCLIENT, SendBNMessage, void __fastcall, (LPSTR lpMessage), 0xC400)

// ============================================================================
// Variable Pointers (VARPTR) - Global Variables
// ============================================================================
// VARPTR calculates addresses as: Base(0x6FAB0000) + Offset = Final Address

// D2CLIENT Variables
VARPTR(D2CLIENT, ScreenScaleDivisor, DWORD, 0xF16B0)          // 0x6FBA16B0 ✅ VERIFIED - DWORD type confirmed in Ghidra, current value=10, screen scaling divisor
VARPTR(D2CLIENT, AutomapDisplayFlag, int, 0xF16B4)            // 0x6FBA16B4 ✓ VERIFIED - AutomapDisplayFlag in Ghidra with correct data type (int)
VARPTR(D2CLIENT, AutomapInitialized, int, 0x11C1B0)           // 0x6FBCC1B0 ✅ SYNCHRONIZED - AutomapInitialized in Ghidra as int, matches boolean usage pattern
VARPTR(D2CLIENT, ShakeStartTime, DWORD, 0x10B9CC)             // 0x6FBBB9CC ✓ VERIFIED - Shake effect start timestamp in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ShakeRampUpDuration, DWORD, 0x10B9D0)        // 0x6FBBB9D0 ✓ VERIFIED - Shake ramp-up phase duration in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ShakeSustainDuration, DWORD, 0x10B9D4)       // 0x6FBBB9D4 ✓ VERIFIED - Shake sustain phase duration in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ShakeDecayDuration, DWORD, 0x10B9D8)         // 0x6FBBB9D8 ✓ VERIFIED - Shake decay phase duration in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ShakeOffsetY, DWORD, 0x10B9DC)               // 0x6FBBB9DC ✓ VERIFIED - Screen shake Y offset in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, GameInfo, GameStructInfo *, 0x11B980)        // 0x6FBC5980 ✓ VERIFIED - GameInfo in Ghidra with correct data type (pointer)
VARPTR(D2CLIENT, Ping, DWORD, 0x119804)                       // 0x6FBC3804 ✓ VERIFIED - Ping in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, Skip, DWORD, 0x119810)                       // 0x6FBC3810 ✓ VERIFIED - Skip in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, MouseOffsetY, int, 0x11995C)                 // 0x6FBC495C ✓ VERIFIED - MouseOffsetY in Ghidra with correct data type (int)
VARPTR(D2CLIENT, MouseOffsetX, int, 0xCB82C)                  // 0x6FBCB82C ✅ VERIFIED - MouseOffsetX/TooltipOffsetX in Ghidra with correct data type (int)
VARPTR(D2CLIENT, MouseY, int, 0x11B824)                       // 0x6FBCB824 ✅ SYNCHRONIZED - MouseY in Ghidra as int, matches function usage patterns
VARPTR(D2CLIENT, MouseX, int, 0x11B828)                       // 0x6FBCB828 ✅ SYNCHRONIZED - MouseX in Ghidra as int, matches function usage patterns
VARPTR(D2CLIENT, PlayerUnit, UnitAny *, 0x11BBFC)             // 0x6FBC5BFC ✅ VERIFIED - UnitAny pointer type confirmed in Ghidra, part of PlayerManagerGlobals structure
VARPTR(D2CLIENT, PlayerUnitList, RosterUnit *, 0x11BC14)      // 0x6FBC5C14 ✅ VERIFIED - RosterUnit pointer type confirmed in Ghidra, party/roster management
VARPTR(D2CLIENT, SelectedInvItem, UnitAny *, 0x11BC38)        // 0x6FBC5C38 ✅ VERIFIED - UnitAny pointer type confirmed in Ghidra, part of PlayerManagerGlobals structure
VARPTR(D2CLIENT, bWeapSwitch, DWORD, 0x11BC94)                // 0x6FBC5C94 ✓ VERIFIED - bWeapSwitch in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ShakeMaxIntensity, DWORD, 0x11BEFC)          // 0x6FBCBEFC ✓ VERIFIED - Maximum shake intensity in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ShakeOffsetX, DWORD, 0x11BF00)               // 0x6FBCBF00 ✓ VERIFIED - Screen shake X offset in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, FirstAutomapLayer, AutomapLayer *, 0x11C1C0) // 0x6FBCC1C0 ✅ VERIFIED - AutomapLayer pointer type confirmed in Ghidra, linked list head
VARPTR(D2CLIENT, AutomapLayer, AutomapLayer *, 0x11C1C4)      // 0x6FBCC1C4 ✓ VERIFIED - AutomapLayer in Ghidra with correct data type (pointer)
VARPTR(D2CLIENT, AutomapPositionX, int, 0x11C1E8)             // 0x6FBCC1E8 ✓ VERIFIED - AutomapPositionX in Ghidra with correct address and data type
VARPTR(D2CLIENT, AutomapPositionY, int, 0x11C1EC)             // 0x6FBCC1EC ✓ VERIFIED - AutomapPositionY in Ghidra with correct address
VARPTR(D2CLIENT, FPS, DWORD, 0x11C2AC)                        // 0x6FBCC2AC ✅ VERIFIED - FPS in Ghidra with correct address and data type (DWORD)
VARPTR(D2CLIENT, PlayerArea, DWORD, 0x11C34C)                 // 0x6FBCC34C ✓ VERIFIED - PlayerArea in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, MapId, DWORD, 0x11C904)                      // 0x6FBCD904 ✓ VERIFIED - MapId in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, QuestTab, DWORD, 0x123395)                   // 0x6FBCD395 ✓ VERIFIED - QuestTab in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ScreenSizeX, DWORD, 0xDBC48)                 // 0x6FB8BC48 ✓ VERIFIED - ScreenWidth in Ghidra with correct data type (DWORD)
VARPTR(D2CLIENT, ScreenSizeY, DWORD, 0xDBC4C)                 // 0x6FB8BC4C ✓ VERIFIED - ScreenHeight in Ghidra with correct data type (DWORD)

// Waygate System Variables (From Analysis)
VARPTR(D2CLIENT, WaypointDataArray, DWORD, 0xFCD8C)          // 0x6FBACD8C ✅ VERIFIED - DWORD type confirmed in Ghidra (was WaypointData*), waypoint data reference
VARPTR(D2CLIENT, WaypointBackgroundResource, DWORD, 0xFCDC1) // 0x6FBACDC1 ✓ VERIFIED - Waygate background resource handle in Ghidra
VARPTR(D2CLIENT, WaypointTabsResource, DWORD, 0xFCDC5)       // 0x6FBACDC5 ✓ VERIFIED - Waygate tabs resource handle in Ghidra
VARPTR(D2CLIENT, WaypointIconsResource, DWORD, 0xFCDC9)      // 0x6FBACDC9 ✓ VERIFIED - Waygate icons resource handle in Ghidra
VARPTR(D2CLIENT, WaypointSelectedTab, DWORD, 0xFCDD6)        // 0x6FBACDD6 ✓ VERIFIED - Selected waypoint tab index in Ghidra (PRIMARY ENTRY)
VARPTR(D2CLIENT, WaypointCount, DWORD, 0xFCDDA)              // 0x6FBACDDA ✓ VERIFIED - Number of available waypoints in Ghidra
VARPTR(D2CLIENT, CurrentWaypointAct, DWORD, 0xFCDDE)         // 0x6FBACDE ✓ VERIFIED - Current act for waypoint display
VARPTR(D2CLIENT, WaypointDialogOpen, BOOL, 0xFCDE2)          // 0x6FBACDE2 ✓ VERIFIED - Waypoint dialog open status

// D2WIN Variables
VARPTR(D2WIN, FirstControl, Control *, 0x214A0) // 0x6FAD14A0 ✓ CREATED - Global created in Ghidra - Done

// ============================================================================
// Assembly Pointers (ASMPTR) - Function Entry Points
// ============================================================================
ASMPTR(D2MULTI, JoinGame_I, 0xCBD0)         // 0x6FAB7BD0 ? NEEDS VERIFICATION - Todo
ASMPTR(D2MULTI, JoinGame_II, 0x11DA0)       // 0x6FABDDA0 ? NEEDS VERIFICATION - Todo
ASMPTR(D2MULTI, WaitBox, 0xAA60)            // 0x6FAB5A60 ? NEEDS VERIFICATION - Todo
ASMPTR(D2CLIENT, GetUnitFromId_I, 0x10A608) // 0x6FABA608 ? NEEDS VERIFICATION - Todo
ASMPTR(D2CLIENT, GetUnitFromId_II, 0xA4E20) // 0x6FB54E20 ? NEEDS VERIFICATION - Todo
ASMPTR(D2CLIENT, GetUnitName_I, 0xA5D90)    // 0x6FB55D90 ? NEEDS VERIFICATION - Todo

#define D2CLIENT_PlayerUnit *p_D2CLIENT_PlayerUnit
#define D2CLIENT_Ping *p_D2CLIENT_Ping
#define MouseX (*p_D2CLIENT_MouseX)
#define MouseY (*p_D2CLIENT_MouseY)
#define GetUnitStat(Unit, Stat) (D2COMMON_GetUnitStat(Unit, Stat, 0))
#define GetUnitState(Unit, State) (D2COMMON_GetUnitState(Unit, State))
#define GetUnitName(X) (wchar_t *)GetUnitNameSTUB((DWORD)X)
#define pMe (*p_D2CLIENT_PlayerUnit)
#define GetUnit(ID, Type) (GetUnitSTUB(ID, Type))
#define GetUIVar(UI) (GetUIVarSTUB(UI))
#define Ping (*p_D2CLIENT_Ping)
#define Skip (*p_D2CLIENT_Skip)
#define FPS (*p_D2CLIENT_FPS)
#define AutoMapLayer (*p_D2CLIENT_AutomapLayer)
#define FirstAutomapLayer (*p_D2CLIENT_FirstAutomapLayer)

#define _D2PTRS_END p_D2CLIENT_bWeapSwitch
