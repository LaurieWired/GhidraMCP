#pragma once

#ifndef _D2STRUCTS_H
#define _D2STRUCTS_H

struct TargetInfo;
struct LevelNameInfo;
struct UnitAny;
struct Room1;
struct RoomTile;
struct PresetUnit;
struct Room2;
struct Level;
struct Act;
struct ActMisc;
struct RosterUnit;
struct OverheadMsg;

typedef RoomTile* LPROOMTILE;
typedef PresetUnit* LPPRESETUNIT;

typedef UnitAny* LPUNITANY;
typedef Level* LPLEVEL;
typedef Room2* LPROOM2;
typedef Room1* LPROOM1;



struct TargetInfo {  // Done
	UnitAny* pPlayer;
	WORD	xPos;
	WORD	yPos;
};

struct LevelNameInfo
{
	int nX;
	int nY;
	int nLevelId;
	int nAct;
};

struct InventoryInfo 
{
	int nLocation;
	int nMaxXCells;
	int nMaxYCells;
};

struct GameStructInfo
{
	BYTE _1[0x1B];					//0x00
	char szGameName[0x18];			//0x1B
	char szGameServerIp[0x56];		//0x33
	char szAccountName[0x30];		//0x89
	char szCharName[0x18];			//0xB9
	char szRealmName[0x18];			//0xD1
	BYTE _2[0x158];					//0xE8
	char szGamePassword[0x18];		//0x241
};

struct AutomapCell {  // Done
	DWORD fSaved;					//0x00
	WORD nCellNo;					//0x04
	WORD xPixel;					//0x06
	WORD yPixel;					//0x08
	WORD wWeight;					//0x0A
	AutomapCell *pLess;				//0x0C
	AutomapCell *pMore;				//0x10
};

struct GfxCell {  // Done
	DWORD flags;					//0x00
	DWORD width;					//0x04
	DWORD height;					//0x08
	DWORD xoffs;					//0x0C
	DWORD yoffs;					//0x10
	DWORD _2;						//0x14
	DWORD lpParent;					//0x18
	DWORD length;					//0x1C
	BYTE cols;						//0x20
};


struct InteractStruct
{
	DWORD dwMoveType;			//0x00
	UnitAny* lpPlayerUnit;		//0x04
	UnitAny* lpTargetUnit;		//0x08
	DWORD dwTargetX;			//0x0C
	DWORD dwTargetY;			//0x10
	DWORD _1;					//0x14
	DWORD _2;					//0x18
};

struct CellFile {  // Done
	DWORD dwVersion;				//0x00
	struct {
		WORD dwFlags;
		BYTE mylastcol;
		BYTE mytabno:1;
	};								//0x04
	DWORD eFormat;					//0x08
	DWORD termination;				//0x0C
	DWORD numdirs;					//0x10
	DWORD numcells;					//0x14
	GfxCell *cells[1];				//0x18
};

struct CellContext {  // Done
	DWORD direction;				//0x00
	GfxCell *hCell;					//0x04
	DWORD _1[0xD];					//0x08
	CellFile* pCellFile;			//0x3C
	DWORD _2;						//0x40
	DWORD nCellNo;					//0x44
};

struct AutomapLayer {  // Done
	DWORD nLayerNo;					//0x00
	DWORD fSaved;					//0x04
	AutomapCell *pFloors;			//0x08
	AutomapCell *pWalls;			//0x0C
	AutomapCell *pObjects;			//0x10
	AutomapCell *pExtras;			//0x14
	AutomapLayer *pNextLayer;		//0x18
};

struct AutomapLayer2 {  // Done
	DWORD _1[2];					//0x00
	DWORD nLayerNo;					//0x08
};

struct LevelTxt {  // Done
	DWORD dwLevelNo;				//0x00
	DWORD _1[60];					//0x04
	BYTE _2;						//0xF4
	char szName[40]; //+16e
	char szEntranceText[40];		//0x11D
	char szLevelDesc[41];			//0x145
	wchar_t wName[40];				//0x16E
	wchar_t wEntranceText[40];		//0x1BE
	BYTE nObjGroup[8];				//0x196
	BYTE nObjPrb[8];				//0x19E
};


struct ControlText {  // Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done - Done
	wchar_t* wText; //0x00
	DWORD _1[4];	//0x04
	DWORD dwColor;	//0x14
	DWORD _2;		//0x18
	ControlText* pNext;//0x1C
};

struct Control { //
	DWORD dwType;					//0x00
	DWORD _1[2];					//0x04
	DWORD dwPosX;					//0x0C
	DWORD dwPosY;					//0x10
	DWORD dwSizeX;					//0x14
	DWORD dwSizeY;					//0x18
	DWORD fnCallback;				//0x1C
	DWORD _2;						//0x20
	DWORD fnClick;					//0x24
	DWORD _3[5];					//0x38
	Control *pNext;					//0x3C
	DWORD _4[2];					//0x40
	ControlText* pFirstText;		//0x48
	ControlText* pLastText;			//0x48
	ControlText* pSelectedText;		//0x4C
	DWORD dwSelectStart;			//0x54
	DWORD dwSelectEnd;				//0x58
	union {
		wchar_t wText[256];			//0x5C
		struct {
			DWORD _5[2];			//0x5C
			wchar_t wText2[256];	//0x64
		};
	};
	DWORD dwCursorPos;				//0x25C
	DWORD dwIsCloaked;				//0x260
};

#pragma pack(push)
#pragma pack(1)

struct RoomTile {
	Room2* pRoom2;					//0x00
	RoomTile* pNext;				//0x04
	DWORD _1[2];					//0x08
	DWORD *nNum;					//0x10
};

struct RosterUnit {
	char szName[16];				//0x00
	DWORD dwUnitId;					//0x10
	DWORD dwPartyLife;				//0x14
	DWORD _1;						//0x18
	DWORD dwClassId;                //0x1C
	WORD wLevel;					//0x20
	WORD wPartyId;  				//0x22
	DWORD dwLevelId;                //0x24
	DWORD Xpos;						//0x28
	DWORD Ypos;						//0x2C
	DWORD dwPartyFlags;				//0x30
	BYTE * _5;						//0x34
	DWORD _6[11];					//0x38
	WORD _7;						//0x64
	char szName2[16];				//0x66
	WORD _8;						//0x76
	DWORD _9[2];					//0x78
	RosterUnit * pNext;				//0x80
};

//from mousepad
struct PartyPlayer { 
char name2[0x10]; //+00 
DWORD nUnitId; //+10 
DWORD life; //+14 
DWORD _2[1]; 
DWORD chrtype; //+1c 
WORD chrlvl; //+20 
WORD partyno; //+22 
DWORD _3[4]; 
DWORD flags; //+34 
DWORD mems; //+38 
BYTE _4[0x2a]; 
char name[1]; //+66 
BYTE _5[0x1d]; 
}; 


struct QuestInfo {
	void *pBuffer;					//0x00
	DWORD _1;						//0x04
};

struct Waypoint {
	BYTE flags;						//0x00
};

struct PlayerData {
	char szName[0x10];				//0x00
	QuestInfo *pNormalQuest;		//0x10
	QuestInfo *pNightmareQuest;		//0x14
	QuestInfo *pHellQuest;			//0x18
	Waypoint *pNormalWaypoint;		//0x1c
	Waypoint *pNightmareWaypoint;	//0x20
	Waypoint *pHellWaypoint;		//0x24
};

struct CollMap {
	DWORD dwPosGameX;				//0x00
	DWORD dwPosGameY;				//0x04
	DWORD dwSizeGameX;				//0x08
	DWORD dwSizeGameY;				//0x0C
	DWORD dwPosRoomX;				//0x10
	DWORD dwPosRoomY;				//0x14
	DWORD dwSizeRoomX;				//0x18
	DWORD dwSizeRoomY;				//0x1C
	WORD *pMapStart;				//0x20
	WORD *pMapEnd;					//0x22
};

struct PresetUnit {
	DWORD _1;						//0x00
	DWORD dwTxtFileNo;				//0x04
	DWORD dwPosX;					//0x08
	PresetUnit* pPresetNext;		//0x0C
	DWORD _2;						//0x10
	DWORD dwType;					//0x14
	DWORD dwPosY;					//0x18
};//updated 1.13

struct Level {
   DWORD _1[4];               //0x00
   Room2* pRoom2First;            //0x10
   DWORD _2[2];               //0x14
   DWORD dwPosX;               //0x1C
   DWORD dwPosY;               //0x20
   DWORD dwSizeX;               //0x24
   DWORD dwSizeY;               //0x28
   DWORD _3[96];               //0x2C
   Level *pNextLevel;            //0x1AC
   DWORD _4;                  //0x1B0
   ActMisc * pMisc;            //0x1B4
   DWORD _5[3];               //0x1B8
   DWORD dwSeed[2];            //0x1C4
   DWORD _6;                  //0x1CC
   DWORD dwLevelNo;            //0x1D0
}; //1.13c

struct Room2
{
	DWORD _1[2];			//0x00
	LPROOM2 * pRoom2Near;	//0x08
	DWORD _2[5];			//0x0C
	LPDWORD pType2Info;		//0x20
	LPROOM2 pRoom2Next;		//0x24
	DWORD dwRoomFlags;		//0x28
	DWORD dwRoomsNear;		//0x2C
	LPROOM1 pRoom1;			//0x30
	DWORD dwPosX;			//0x34
	DWORD dwPosY;			//0x38
	DWORD dwSizeX;			//0x3C
	DWORD dwSizeY;			//0x40
	DWORD _3;				//0x44
	DWORD dwPresetType;		//0x48
	LPROOMTILE pRoomTiles;	//0x4C
	DWORD _4[2];			//0x50
	LPLEVEL pLevel;			//0x58
	LPPRESETUNIT pPreset;	//0x5C
};
#pragma pack(pop)

struct Room1
{
	Room1** pRoomsNear; 	//0x00
	DWORD _1[3];			//0x04
	Room2* pRoom2;			//0x10
	DWORD _2[3];			//0x14
	CollMap* Coll;			//0x20
	DWORD dwRoomsNear;		//0x24
	DWORD _3[9];			//0x28
	DWORD dwXStart;			//0x4C
	DWORD dwYStart;			//0x50
	DWORD dwXSize;			//0x54
	DWORD dwYSize;			//0x58
	DWORD _4[6];			//0x5C
	UnitAny* pUnitFirst;	//0x74
	DWORD _5;				//0x78
	Room1* pRoomNext;		//0x7C
};

// updated
struct ActMisc
{
  BYTE _1[0x94];
  DWORD dwStaffTombLevel; // 0x94
  BYTE _2[0x3D4];
  Act *pAct; // 0x46C
  DWORD _3[3];
  Level *pLevelFirst; // 0x47C
};

struct Act
{
	DWORD _1[3];         //0x00
	DWORD dwMapSeed;      //0x0C
	Room1* pRoom1;         //0x10
	DWORD dwAct;         //0x14
	DWORD _2[12];         //0x18
	ActMisc* pMisc;         //0x48 
};

struct Path {
	WORD xOffset;					//0x00
	WORD xPos;						//0x02
	WORD yOffset;					//0x04
	WORD yPos;						//0x06
	DWORD _1[2];					//0x08
	WORD xTarget;					//0x10
	WORD yTarget;					//0x12
	DWORD _2[2];					//0x14
	Room1 *pRoom1;					//0x1C
	Room1 *pRoomUnk;				//0x20
	DWORD _3[3];					//0x24
	UnitAny *pUnit;					//0x30
	DWORD dwFlags;					//0x34
	DWORD _4;						//0x38
	DWORD dwPathType;				//0x3C
	DWORD dwPrevPathType;			//0x40
	DWORD dwUnitSize;				//0x44
	DWORD _5[4];					//0x48
	UnitAny *pTargetUnit;			//0x58
	DWORD dwTargetType;				//0x5C
	DWORD dwTargetId;				//0x60
	BYTE bDirection;				//0x64
};

struct ItemPath {
	DWORD _1[3];					//0x00
	DWORD dwPosX;					//0x0C
	DWORD dwPosY;					//0x10
	//Use Path for the rest
};

struct Stat {
	WORD wSubIndex;					//0x00
	WORD wStatIndex;				//0x02
	DWORD dwStatValue;				//0x04
};

struct StatList {
	DWORD _1[9];					//0x00
	Stat *pStat;					//0x24
	WORD wStatCount1;				//0x28
	WORD wStatCount2;				//0x2A
	DWORD _2[2];					//0x2C
	BYTE *_3;						//0x34
	DWORD _4;						//0x38
	StatList *pNext;				//0x3C
};

struct Inventory {
	DWORD dwSignature;				//0x00
	BYTE *bGame1C;					//0x04
	UnitAny *pOwner;				//0x08
	UnitAny *pFirstItem;			//0x0C
	UnitAny *pLastItem;				//0x10
	DWORD _1[2];					//0x14
	DWORD dwLeftItemUid;			//0x1C
	UnitAny *pCursorItem;			//0x20
	DWORD dwOwnerId;				//0x24
	DWORD dwItemCount;				//0x28
};

struct Light {
	DWORD _1[3];					//0x00
	DWORD dwType;					//0x0C
	DWORD _2[7];					//0x10
	DWORD dwStaticValid;			//0x2C
	int *pnStaticMap;				//0x30
};

struct SkillInfo {
	WORD wSkillId;					//0x00
};

struct Skill {
	SkillInfo *pSkillInfo;			//0x00
	Skill *pNextSkill;				//0x04
	DWORD _1[8];					//0x08
	DWORD dwSkillLevel;				//0x28
	DWORD _2[2];					//0x2C
	DWORD dwFlags;					//0x30
};

struct Info {
	BYTE *pGame1C;					//0x00
	Skill *pFirstSkill;				//0x04
	Skill *pLeftSkill;				//0x08
	Skill *pRightSkill;				//0x0C
};

struct ItemData {
	DWORD dwQuality;				//0x00
	DWORD _1[2];					//0x04
	DWORD dwItemFlags;				//0x0C 1 = Owned by player, 0xFFFFFFFF = Not owned
	DWORD _2[2];					//0x10
	DWORD dwFlags;					//0x18
	DWORD _3[3];					//0x1C
	DWORD dwQuality2;				//0x28
	DWORD dwItemLevel;				//0x2C
	DWORD _4[2];					//0x30
	WORD wPrefix;					//0x38
	WORD _5[2];						//0x3A
	WORD wSuffix;					//0x3E
	DWORD _6;						//0x40
	BYTE BodyLocation;				//0x44
	BYTE ItemLocation;				//0x45 Non-body/belt location (Body/Belt == 0xFF)
	BYTE _7;						//0x46
	WORD _8;						//0x47
	DWORD _9[4];					//0x48
	Inventory *pOwnerInventory;		//0x5C
	DWORD _10;						//0x60
	UnitAny *pNextInvItem;			//0x64
	BYTE _11;						//0x68
	BYTE NodePage;					//0x69 Actual location, this is the most reliable by far
	WORD _12;						//0x6A
	DWORD _13[6];					//0x6C
	UnitAny *pOwner;				//0x84
};

struct ItemTxt {
	wchar_t szName2[0x40];			//0x00
	union {
		DWORD dwCode;
		char szCode[4];
	};								//0x40
	BYTE _2[0x70];					//0x84
	WORD nLocaleTxtNo;				//0xF4
	BYTE _2a[0x19];					//0xF7
	BYTE xSize;						//0xFC
	BYTE ySize;						//0xFD
	BYTE _2b[13];					//0xFE
	BYTE nType;						//0x11E
	BYTE _3[0x0d];					//0x11F
	BYTE fQuest;					//0x12A
};

struct MonsterTxt {
	BYTE _1[0x6];					//0x00
	WORD nLocaleTxtNo;				//0x06
	WORD flag;						//0x08
	WORD _1a;						//0x0A
	union {
		DWORD flag1;				//0x0C
		struct {
			BYTE flag1a;			//0x0C
			BYTE flag1b;			//0x0D
			BYTE flag1c[2];			//0x0E
		};
	};
	BYTE _2[0x22];					//0x10
	WORD velocity;					//0x32
	BYTE _2a[0x52];					//0x34
	WORD tcs[3][4];					//0x86
	BYTE _2b[0x52];					//0x9E
	wchar_t szDescriptor[0x3c];		//0xF0
	BYTE _3[0x1a0];					//0x12C
};

struct MonsterData {
	BYTE _1[22];					//0x00
	struct
	{
		BYTE fUnk:1;
		BYTE fNormal:1;
		BYTE fChamp:1;
		BYTE fBoss:1;
		BYTE fMinion:1;
	};								//0x16
	WORD _2;						//0x17
	DWORD _3;						//0x18
	BYTE anEnchants[9];				//0x1C
	BYTE _4;						//0x25
	WORD wUniqueNo;					//0x26
	DWORD _5;						//0x28
	struct {
		wchar_t wName[28];
	};								//0x2C
};

struct ObjectTxt {
	char szName[0x40];				//0x00
	wchar_t wszName[0x40];			//0x40
	BYTE _1[4];						//0xC0
	BYTE nSelectable0;				//0xC4
	BYTE _2[0x87];					//0xC5
	BYTE nOrientation;				//0x14C
	BYTE _2b[0x19];					//0x14D
	BYTE nSubClass;					//0x166
	BYTE _3[0x11];					//0x167
	BYTE nParm0;					//0x178
	BYTE _4[0x39];					//0x179
	BYTE nPopulateFn;				//0x1B2
	BYTE nOperateFn;				//0x1B3
	BYTE _5[8];						//0x1B4
	DWORD nAutoMap;					//0x1BB
};

struct ObjectData {
	ObjectTxt *pTxt;				//0x00
	DWORD Type;						//0x04 (0x0F would be a Exp Shrine)
	DWORD _1[8];					//0x08
	char szOwner[0x10];				//0x28
};

struct ObjectPath {
	Room1 *pRoom1;					//0x00
	DWORD _1[2];					//0x04
	DWORD dwPosX;					//0x0C
	DWORD dwPosY;					//0x10
	//Leaving rest undefined, use Path
};

struct UnitAny
{
	DWORD dwType;					//0x00
	DWORD dwTxtFileNo;				//0x04
	DWORD _1;						//0x08
	DWORD dwUnitId;					//0x0C
	DWORD dwMode;					//0x10
	union
	{
		PlayerData *pPlayerData;
		ItemData *pItemData;
		MonsterData *pMonsterData;
		ObjectData *pObjectData;
		//TileData *pTileData doesn't appear to exist anymore
	};								//0x14
	DWORD dwAct;					//0x18
	Act *pAct;						//0x1C
	DWORD dwSeed[2];				//0x20
	DWORD _2;						//0x28
	union
	{
		Path *pPath;
		ItemPath *pItemPath;
		ObjectPath *pObjectPath;
	};								//0x2C
	DWORD _3[5];					//0x30
	DWORD dwGfxFrame;				//0x44
	DWORD dwFrameRemain;			//0x48
	WORD wFrameRate;				//0x4C
	WORD _4;						//0x4E
	BYTE *pGfxUnk;					//0x50
	DWORD *pGfxInfo;				//0x54
	DWORD _5;						//0x58
	StatList *pStats;				//0x5C
	Inventory *pInventory;			//0x60
	Light *ptLight;					//0x64
	DWORD _6[9];					//0x68
	WORD wX;						//0x8C
	WORD wY;						//0x8E
	DWORD _7;						//0x90
	DWORD dwOwnerType;				//0x94
	DWORD dwOwnerId;				//0x98
	DWORD _8[2];					//0x9C
	OverheadMsg* pOMsg;				//0xA4
	Info *pInfo;					//0xA8
	DWORD _9[6];					//0xAC
	DWORD dwFlags;					//0xC4
	DWORD dwFlags2;					//0xC8
	DWORD _10[5];					//0xCC
	LPUNITANY pChangedNext;			//0xE0
	LPUNITANY pRoomNext;			//0xE4
	LPUNITANY pListNext;			//0xE8 -> 0xD8
	CHAR szNameCopy[0x10];			//+0x66
};

struct BnetData
{
	DWORD dwId;					//0x00
	DWORD dwId2;				//0x04
	DWORD _1[3];				//0x08
	DWORD dwId3;				//0x14
	WORD Unk3;					//0x18
	char szGameName[22];		//0x1A
	char szGameIP[16];			//0x30
	DWORD _2[16];				//0x40
	DWORD dwId4;				//0x80
	DWORD _3;					//0x84
	char szAccountName[48];		//0x88
	char szPlayerName[24];		//0xB8
	char szRealmName[8];		//0xD0
	BYTE _4[273];				//0xD8
	BYTE nCharClass;			//0x1E9
	BYTE nCharFlags;			//0x1EA
	BYTE nMaxDiff;				//0x1EB
	BYTE _5[31];				//0x1EC
	BYTE nDifficulty;			//0x20B
	void *_6;					//0x20C
	DWORD _7[5];				//0x210
	WORD _8;					//0x224
	BYTE _9;					//0x226
	char szRealmName2[24];		//0x227
	char szGamePass[24];		//0x23F
	char szGameDesc[256];		//0x257
	WORD _10;					//0x348
	BYTE _11;					//0x34B
};


struct WardenClientRegion_t
{
	DWORD cbAllocSize; //+00
	DWORD offsetFunc1; //+04
	DWORD offsetRelocAddressTable; //+08
	DWORD nRelocCount; //+0c
	DWORD offsetWardenSetup; //+10
	DWORD _2[2];
	DWORD offsetImportAddressTable; //+1c
	DWORD nImportDllCount; //+20
	DWORD nSectionCount; //+24
};

struct SMemBlock_t {
	DWORD _1[6];
	DWORD cbSize; //+18
	DWORD _2[31];
	BYTE data[1]; //+98
};

struct WardenClient_t {
	WardenClientRegion_t* pWardenRegion; //+00
	DWORD cbSize; //+04
	DWORD nModuleCount; //+08
	DWORD param; //+0c
	DWORD fnSetupWarden; //+10
};

struct WardenIATInfo_t
{
	DWORD offsetModuleName;
	DWORD offsetImportTable;
};

struct AttackStruct
{
	DWORD dwAttackType;			//0x00
	UnitAny* lpPlayerUnit;		//0x04
	UnitAny* lpTargetUnit;		//0x08
	DWORD dwTargetX;			//0x0C
	DWORD dwTargetY;			//0x10
	DWORD _1;					//0x14
	DWORD _2;					//0x18
};

struct Skill_t {
	CHAR			name[64];
	WORD			skillID;
};


/*
Akara NPCEntry

0   94 00 00 00 03 00 00 00  ï¿½.......
8   35 0D 44 0D 00 00 00 00  5.D.....
10  00 00 B0 AA B0 6F 90 BD  ..ï¿½ï¿½ï¿½oï¿½ï¿½
18  B0 6F 00 00 00 00 00 00  ï¿½o......
20  00 00 00 00 00 00 01     .......
*/
// Thanks to Darawk for hooking me up with this preprocessor commands!
#pragma pack(push)
#pragma pack(1)

typedef struct  {
	DWORD dwNPCClassId;
	DWORD dwEntryAmount;
	WORD wEntryId1;
	WORD wEntryId2;
	WORD wEntryId3;
	WORD wEntryId4;	
	WORD _1;
	DWORD dwEntryFunc1;
	DWORD dwEntryFunc2; 
	DWORD dwEntryFunc3; 
	DWORD dwEntryFunc4;
	BYTE _2[5];
} NPCMenu;

struct OverheadMsg {
	DWORD _1;
	DWORD dwTrigger;
	DWORD _2[2];
	CHAR Msg[232];
};

#pragma pack(pop)

struct D2MSG {
	HWND myHWND;
	char lpBuf[256];
};


struct InventoryLayout
{
	BYTE SlotWidth;
	BYTE SlotHeight;
	BYTE unk1;
	BYTE unk2;
	DWORD Left;
	DWORD Right;
	DWORD Top;
	DWORD Bottom;
	BYTE SlotPixelWidth;
	BYTE SlotPixelHeight;
};

struct MpqTable
{

};

struct sgptDataTable
{
	MpqTable*	pPlayerClass;
	DWORD		dwPlayerClassRecords;
	MpqTable*	pBodyLocs;
	DWORD		dwBodyLocsRecords;
	MpqTable*	pStorePage;
	DWORD		dwStorePageRecords;
	MpqTable*	pElemTypes;
};

/*
Thanks to 99Elite for posting the list at ladderhall.com!

Layout of sgptDataTables

+0     :  ptr to playerclass.bin
+4     :  num records in playerclass.bin
+8     :  ptr to bodylocs.bin
+c     :  num records in bodylocs.bin
+10   :  ptr to storepage.bin
+14   :  num records in storepage.bin
+18   :  ptr to elemtypes.bin
+1c   :  num records in elemtypes.bin
+20   :  ptr to hitclass.bin
+24   :  num records in hitclass.bin
+28   :  ptr to monmode.bin
+2c   :  num records in monmode.bin
+30   :  ptr to plrmode.bin
+34   :  num records in plrmode.bin
+38   :  ptr to skillcalc.bin
+3c   :  num records in skillcalc.bin
+44   :  ptr to skillscode.bin
+48   :  num records in skillscode.bin
+50   :  ptr to skilldesccode.bin
+54   :  num records in skilldesccode.bin
+58   :  ptr to misscalc.bin
+5c   :  num records in misccalc.bin
+64   :  ptr to misscode.bin
+68   :  numrecords in misccode.bin
+70   :  ptr to events.bin
+74   :  numrecords in events.bin
+88   :  ptr to monai.bin
+8c    : num records in monai.bin
+A4   :  ptr to properties.bin
+Ac   :  num records in properties.bin
+b4   :  ptr to hiredesc.bin
+b8   :  num records in hiredesc.bin
+194 :  ptr to sounds.bin
+19c :  num records in sounds.bin
+1a0 :  ptr to heirling.bin
+1a4 :  num records in heirling.bin
+9a8 :  ptr to npc.txt
+9ac :  num records in npc.txt
+9b0 :  ptr to colors.bin
+9b4 :  num records in colors.bin
+a78 :  ptr to monstats.bin
+a80 :  num records in monstats.bin
+a84 :  ptr to monsounds.bin
+a8c :  num records in monsunds.bin
+a90 :  ptr to monstats2.bin
+a98 :  num records in monstats2.bin
+a9c :  ptr to monplace.bin
+aa0 :  numrecirds in monplace.bin
+aa8 :  ptr to monprest.bin
+aac :  ptr to monprest.bin (again) // check this
+ad4 :  ptr to superuniques.bin
+adc :  num records in superuniques.bin
+b64 :  missiles.bin
+b6c :  num records in missiles.bin
+b70 :  ptr to monlvl.bin
+b74 :  num records in monlvl.bin
+b78 :  ptr to monseq.bin
+b7c :  num records in monseq.bin
+b94 :  num records in skillsdesc.bin
+b98 :  ptr to skills.bin
+ba0 :  num records in skills table
+bbc :  ptr to overlay.bin
+bc0 :  num records in overlay.bin
+bc4 :  charstats table
+bcc :  ptr to itemstatcost table
+bd4 :  num records in itemstatcost
+be0 :  ptr to monequip.bin
+be4 :  num records in monequip.bin
+bf8  :  ptr to itemtypes.bin
+bfc  :  num records in itemtypes.bin
+c0c :  ptr to sets.bin
+c10 :  num records in sets.bin
+c18 :  ptr to setitems.bin
+c1c :  num records in setitems.bin
+c24 :  ptr to uniqueitems.bin
+c28 :  num records in uniqueitems.bin
+c30 :  ptr to monprop.bin
+c34 :  num records in monprop.bin
+c3c :  ptr to montype.bin
+c40 :  num records in montype.bin
+c50 :  ptr to monumod.bin
+c54 :  num records in monummod.bin
+c58 :  ptr to levels.bin
+c5c :  num records in levels.bin
+c60 :  ptr to lvldefs.bin
+c64 :  ptr to lvlPrest.bin
+c68 :  num records in lvlPrest.bin
+cb8 :  ptr to chartemplate.bin
+cbc :  num records in chartemplate.bin
+cc0 :  ptr to arena.bin
+cc4 :  ptr to lvlTypes.bin
+cd0 :  num records in lvlTypes.bin
+cd4 :  ptr to lvlwarp.bin
+cd8 :  num records in lvlwarp.bin
+cdc :  ptr to lvlmaze.bin
+ce0 :  num records in lvlmaze.bin
+ce4 :  ptr to levelsub.bin
+ce8 :  num records in levelsub.bin
+d04 :  ptr to cubemain.bin
+d08 :  num records in cubemain.bin
*/

//////////////////////////////////////////////////////////////////////
// Unit Affection ID Definition
//////////////////////////////////////////////////////////////////////
#define AFFECT_NONE                                                  0
#define AFFECT_FREEZE                                                1
#define AFFECT_POISON                                                2
#define AFFECT_RESISTFIRE                                            3
#define AFFECT_RESISTCOLD                                            4
#define AFFECT_RESISTLIGHT                                           5
#define AFFECT_RESISTMAGIC                                           6
#define AFFECT_PLAYERBODY                                            7
#define AFFECT_RESISTALL                                             8
#define AFFECT_AMPLIFYDAMAGE                                         9
#define AFFECT_FROZENARMOR                                           10
#define AFFECT_COLD                                                  11
#define AFFECT_INFERNO                                               12
#define AFFECT_BLAZE                                                 13
#define AFFECT_BONEARMOR                                             14
#define AFFECT_CONCENTRATE                                           15
#define AFFECT_ENCHANT                                               16
#define AFFECT_INNERSIGHT                                            17
#define AFFECT_SKILL_MOVE                                            18
#define AFFECT_WEAKEN                                                19
#define AFFECT_CHILLINGARMOR                                         20
#define AFFECT_STUNNED                                               21
#define AFFECT_SPIDERLAY                                             22
#define AFFECT_DIMVISION                                             23
#define AFFECT_SLOWED                                                24
#define AFFECT_FETISHAURA                                            25
#define AFFECT_SHOUT                                                 26
#define AFFECT_TAUNT                                                 27
#define AFFECT_CONVICTION                                            28
#define AFFECT_CONVICTED                                             29
#define AFFECT_ENERGYSHIELD                                          30
#define AFFECT_VENOMCLAWS                                            31
#define AFFECT_BATTLEORDERS                                          32
#define AFFECT_MIGHT                                                 33
#define AFFECT_PRAYER                                                34
#define AFFECT_HOLYFIRE                                              35
#define AFFECT_THORNS                                                36
#define AFFECT_DEFIANCE                                              37
#define AFFECT_THUNDERSTORM                                          38
#define AFFECT_LIGHTNINGBOLT                                         39
#define AFFECT_BLESSEDAIM                                            40
#define AFFECT_VIGOR	                                                41
#define AFFECT_CONCENTRATION                                         42
#define AFFECT_HOLYFREEZE                                            43
#define AFFECT_HOLYFREEZECHILL                                       44
#define AFFECT_CLEANSING                                             45
#define AFFECT_HOLYSHOCK                                             46
#define AFFECT_SANCTUARY                                             47
#define AFFECT_MEDITATION                                            48
#define AFFECT_FANATICISM                                            49
#define AFFECT_REDEMPTION                                            50
#define AFFECT_BATTLECOMMAND                                         51
#define AFFECT_PREVENTHEAL                                           52
#define AFFECT_CONVERSION                                            53
#define AFFECT_UNINTERRUPTABLE                                       54
#define AFFECT_IRONMAIDEN                                            55
#define AFFECT_TERROR                                                56
#define AFFECT_ATTRACT                                               57
#define AFFECT_LIFETAP                                               58
#define AFFECT_CONFUSE                                               59
#define AFFECT_DECREPIFY                                             60
#define AFFECT_LOWERRESIST                                           61
#define AFFECT_OPENWOUNDS                                            62
#define AFFECT_DOPPLEZON                                             63
#define AFFECT_CRITICALSTRIKE                                        64
#define AFFECT_DODGE                                                 65
#define AFFECT_AVOID                                                 66
#define AFFECT_PENETRATE                                             67
#define AFFECT_EVADE                                                 68
#define AFFECT_PIERCE                                                69
#define AFFECT_WARMTH                                                70
#define AFFECT_FIREMASTERY                                           71
#define AFFECT_LIGHTNINGMASTERY                                      72
#define AFFECT_COLDMASTERY                                           73
#define AFFECT_SWORDMASTERY                                          74
#define AFFECT_AXEMASTERY                                            75
#define AFFECT_MACEMASTERY                                           76
#define AFFECT_POLEARMMASTERY                                        77
#define AFFECT_THROWINGMASTERY                                       78
#define AFFECT_SPEARMASTERY                                          79
#define AFFECT_INCREASEDSTAMINA                                      80
#define AFFECT_IRONSKIN                                              81
#define AFFECT_INCREASEDSPEED                                        82
#define AFFECT_NATURALRESISTANCE                                     83
#define AFFECT_FINGERMAGECURSE                                       84
#define AFFECT_NOMANAREGEN                                           85
#define AFFECT_JUSTHIT                                               86
#define AFFECT_SLOWMISSILES                                          87
#define AFFECT_SHIVERARMOR                                           88
#define AFFECT_BATTLECRY                                             89
#define AFFECT_BLUE                                                  90
#define AFFECT_RED                                                   91
#define AFFECT_DEATH_DELAY                                           92
#define AFFECT_VALKYRIE                                              93
#define AFFECT_FRENZY                                                94
#define AFFECT_BERSERK                                               95
#define AFFECT_REVIVE                                                96
#define AFFECT_ITEMFULLSET                                           97
#define AFFECT_SOURCEUNIT                                            98
#define AFFECT_REDEEMED                                              99
#define AFFECT_HEALTHPOT                                             100
#define AFFECT_HOLYSHIELD                                            101
#define AFFECT_JUST_PORTALED                                         102
#define AFFECT_MONFRENZY                                             103
#define AFFECT_CORPSE_NODRAW                                         104
#define AFFECT_ALIGNMENT                                             105
#define AFFECT_MANAPOT                                               106
#define AFFECT_SHATTER                                               107
#define AFFECT_SYNC_WARPED                                           108
#define AFFECT_CONVERSION_SAVE                                       109
#define AFFECT_PREGNANT                                              110
#define AFFECT_111                                                   111
#define AFFECT_RABIES                                                112
#define AFFECT_DEFENSE_CURSE                                         113
#define AFFECT_BLOOD_MANA                                            114
#define AFFECT_BURNING                                               115
#define AFFECT_DRAGONFLIGHT                                          116
#define AFFECT_MAUL                                                  117
#define AFFECT_CORPSE_NOSELECT                                       118
#define AFFECT_SHADOWWARRIOR                                         119
#define AFFECT_FERALRAGE                                             120
#define AFFECT_SKILLDELAY                                            121
#define AFFECT_PROGRESSIVE_DAMAGE                                    122
#define AFFECT_PROGRESSIVE_STEAL                                     123
#define AFFECT_PROGRESSIVE_OTHER                                     124
#define AFFECT_PROGRESSIVE_FIRE                                      125
#define AFFECT_PROGRESSIVE_COLD                                      126
#define AFFECT_PROGRESSIVE_LIGHTNING                                 127
#define AFFECT_SHRINE_ARMOR                                          128
#define AFFECT_SHRINE_COMBAT                                         129
#define AFFECT_SHRINE_RESIST_LIGHTNING                               130
#define AFFECT_SHRINE_RESIST_FIRE                                    131
#define AFFECT_SHRINE_RESIST_COLD                                    132
#define AFFECT_SHRINE_RESIST_POISON                                  133
#define AFFECT_SHRINE_SKILL                                          134
#define AFFECT_SHRINE_MANA_REGEN                                     135
#define AFFECT_SHRINE_STAMINA                                        136
#define AFFECT_SHRINE_EXPERIENCE                                     137
#define AFFECT_FENRIS_RAGE                                           138
#define AFFECT_WOLF                                                  139
#define AFFECT_BEAR                                                  140
#define AFFECT_BLOODLUST                                             141
#define AFFECT_CHANGECLASS                                           142
#define AFFECT_ATTACHED                                              143
#define AFFECT_HURRICANE                                             144
#define AFFECT_ARMAGEDDON                                            145
#define AFFECT_INVIS                                                 146
#define AFFECT_BARBS                                                 147
#define AFFECT_WOLVERINE                                             148
#define AFFECT_OAKSAGE                                               149
#define AFFECT_VINE_BEAST                                            150
#define AFFECT_CYCLONEARMOR                                          151
#define AFFECT_CLAWMASTERY                                           152
#define AFFECT_CLOAK_OF_SHADOWS                                      153
#define AFFECT_RECYCLED                                              154
#define AFFECT_WEAPONBLOCK                                           155
#define AFFECT_CLOAKED                                               156
#define AFFECT_BURSTOFSPEED                                          157
#define AFFECT_BLADESHIELD                                           158
#define AFFECT_FADE                                                  159

typedef struct ItemStruct_t {

	BYTE	MessageID;
	BYTE	Action;
	BYTE	MessageSize;
	BYTE	ItemType;
	DWORD	ItemID;
	
	// flags
	BOOL	isSocketsFull;
	BOOL	isIdentified;
	BOOL	isEthereal;
	BOOL	isSwitchin;
	BOOL	isSwitchout;
	BOOL	isBroken;
	BOOL	fromBelt;
	BOOL	hasSockets;
	BOOL	isJustGenerated;
	BOOL	isEar;
	BOOL	isStartitem;
	BOOL	isMiscItem;			// unverified
	BOOL	isPersonalized;
	BOOL	isGamble;
	BOOL	isRuneWord;			// unverified
	BOOL	isMagicExtra;		// unverified

	WORD	MPQVersionField;
	BYTE	Location;
	WORD	PositionX;
	WORD	PositionY;
	char	ItemCode[5];
	BYTE	ItemLevel;

	// gold specific
	BOOL	GoldSize;
	DWORD	GoldAmount;

	//////////////////////////// CHECKS
	BOOL	DoNotTryWhenFull;
	
} ITEMSTRUCT;
enum UnitNo {
	UNITNO_PLAYER	= 0,
	UNITNO_MONSTER	= 1,
	UNITNO_OBJECT	= 2,
	UNITNO_MISSILE	= 3,
	UNITNO_ITEM		= 4,
	UNITNO_ROOMTILE	= 5
};
enum { UNIT_PLAYER, UNIT_MONSTER, UNIT_OBJECT, UNIT_MISSILE, UNIT_ITEM, UNIT_ROOMTILE, UNIT_ALL };
#endif
