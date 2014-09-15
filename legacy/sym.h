/*********************************************************************
  sym.h	.sym file definitions
  $Id: sym.h,v 1.4 2008/05/24 23:28:21 Steven Exp $

  29 Jul 04 SHL Restore default packing
  31 Jul 04 SHL Annotate
  23 Mar 05 SHL Correct dwFileOffset
  30 Jun 05 SHL Correct pSymDef doc
  06 May 08 SHL Add safety parens
*/

/* Pointer means offset from beginning of file or beginning of struct */

#pragma pack(1)

typedef struct {
  unsigned short int ppNextMap;     /* 00 - paragraph addr of next map            */
  unsigned char      bFlags;        /* 02 - symbol types                          */
  unsigned char      bReserved1;    /* 03 - reserved                              */
  unsigned short int pSegEntry;     /* 04 - segment entry point value             */
  unsigned short int cConsts;       /* 06 - count of constants in map             */
  unsigned short int pConstDef;     /* 08 - pointer to constant chain             */
  unsigned short int cSegs;         /* 10 - count of segments in map              */
  unsigned short int ppSegDef;      /* 12 - paragraph offset to first segment     */
  unsigned char      cbMaxSym;      /* 14 - maximum symbol-name length            */
  unsigned char      cbModName;     /* 15 - length of module name                 */
  char               achModName[1]; /* 16 - cbModName bytes of module-name member */
} MAPDEF;

typedef struct {
  unsigned short int ppNextMap;     /* 00 - always zero                           */
  unsigned char      release;       /* 02 - release number (minor version number) */
  unsigned char      version;       /* 03 - major version number                  */
} LAST_MAPDEF;

// Version/release info of some SYM generators
//  5.1 - IBM Operating System/2 Symbol File Generator v4.0
//  6.0 - Microsoft Symbol File Generator v6.0
//  4.0 - Nu-Mega MAP File to SYM Converter v2.9

typedef struct {
  unsigned short int ppNextSeg;     /* 00 - paragraph addr of next segment        */
  unsigned short int cSymbols;      /* 02 - count of symbols in list              */
  unsigned short int pSymDef;       /* 04 - offset to symbol chain from SegDef    */
  unsigned short int wSegNum;       /* 06 - segment number                        */
  unsigned short int wInstance0;    /* 08 - instance 0 physical address           */
  unsigned short int wInstance1;    /* 10 - instance 1 physical address           */
  unsigned short int wInstance2;    /* 12 - instance 2 physical address           */
  unsigned char      bFlags;        /* 14 - segment symbol type                   */
  unsigned char      bReserved1;    /* 15 - reserved                              */
  unsigned short int ppLineDef;     /* 16 - para offset of line number record     */
  unsigned char      bIsSegLoaded;  /* 18 - is segment loaded                     */
  unsigned char      bCurrInstance; /* 19 - current instance                      */
  unsigned char      cbSegName;     /* 20 - length of segment name                */
  char               achSegName[1]; /* 21 - cbSegName bytes of segment-name member*/
} SEGDEF;

typedef struct {
  unsigned short int wSymVal;       /* symbol address or constant            */
  unsigned char      cbSymName;     /* length of symbol name                 */
  char               achSymName[1]; /* cbSymName bytes of symbol-name member */
} SYMDEF16;

typedef struct {
  unsigned       int wSymVal;       /* symbol address or constant            */
  unsigned char      cbSymName;     /* length of symbol name                 */
  char               achSymName[1]; /* cbSymName bytes of symbol-name member */
} SYMDEF32;

typedef struct {
  unsigned short int ppNextLine;    /* 00 - para offset to next linedef (0 if last) */
  unsigned short int wReserved1;    /* 02 - reserved                                */
  unsigned short int pLines;        /* 04 - para offset line info records           */
  unsigned short int FileHandle;    // 06 - file handle
  unsigned short int cLines;        /* 08 - number of line entries                  */
  unsigned char      cbFileName;    /* 10 - length of filename                      */
  char               achFileName[1];/* 11 - cbFileName bytes of filename            */
} LINEDEF;

typedef struct {
  unsigned short int wCodeOffset;   /* 00 - executable offset from start of segment */
  unsigned long  int dwFileOffset;  /* 02 - source offset from start of file        */
} LINEINF;

#pragma pack()

#define SEGDEFOFFSET(MapDef)     ((unsigned long)MapDef.ppSegDef*16)	// 06 May 08 SHL
#define NEXTSEGDEFOFFSET(SegDef)  ((unsigned long)SegDef.ppNextSeg*16)	// 06 May 08 SHL

#define ASYMPTROFFSET(SegDefOffset,Segdef) (SegDefOffset+SegDef.pSymDef)
#define SYMDEFOFFSET(SegDefOffset,SegDef,n) (ASYMPTROFFSET(SegDefOffset,SegDef)+(n)*(sizeof(unsigned short int)))

#define ACONSTPTROFFSET(MapDef) (MapDef.ppConstDef)
#define CONSTDEFOFFSET(MapDef,n) ((MapDef.ppConstDef)+(n)*(sizeof(unsigned short int)))

#define LINEDEFOFFSET(SegDef) (SegDef.ppLineDef*16))
#define NEXTLINEDEFOFFSET(LineDef) (LineDef.ppNextLine*16)
#define LINESOFFSET(LinedefOffset,LineDef) ((LinedefOffset)+LineDef.pLines)

// The end
