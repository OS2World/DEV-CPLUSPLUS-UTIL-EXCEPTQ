/*****************************************************************************/
/*
 *  exq_dbg.c - IBM HLL (32-bit) debug info parser
 *
 *  Parts of this file are
 *    Copyright (c) 2000-2010 Steven Levine and Associates, Inc.
 *    Copyright (c) 2010 Richard L Walsh
 *
*/
/*****************************************************************************/
/* 24 May 08 SHL fixme to be in debuginfo.h?
 * 24 May 08 SHL fixme to use omf.h everwhere
 * fixme to use omf.h definitions
 * see ow\bld\watcom\h\hll.h
*/
/*****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <fcntl.h>
#include <sys\stat.h>
#include <share.h>
#include <io.h>

#define INCL_DOS
#include <os2.h>

#include <exe.h>
#include <newexe.h>

/* fixme to not need */
#define  FOR_EXEHDR  1        /* avoid define conflicts between newexe.h and exe386.h */
#include <exe386.h>
#include "omf.h"
#include "hlldbg.h"

#include "exq.h"

/*****************************************************************************/

#define MAX_AUTONAMBYTES  64
#define MAX_USERDEFS      150
#define MAX_POINTERS      150
#define MAX_AUTOVARS      50

/** structs used to save info about automatic variables **/

#pragma pack(1)

typedef struct
{
  char      name[MAX_AUTONAMBYTES];
  ULONG     stack_offset;
  USHORT    type_idx;
} XQ_AUTOVARS;

typedef struct
{
  USHORT    idx;
  USHORT    type_index;
  BYTE      filler;
  BYTE      name[33];
} XQ_USERDEF;

typedef struct
{
  USHORT    idx;
  USHORT    type_index;
  BYTE      type_qual;
  BYTE      name[33];
} XQ_POINTERS;

#pragma pack()


/* an agglomeration of data passed between functions intended to
 * reduce stack usage a bit and avoid having to pass 5 or 6 arguments
*/
typedef struct
{
  char *    pszFile;
  USHORT    usSeg;
  ULONG     ulOffset;
  BOOL      fSaveSymbols;
  BOOL      f16Bit;
  INT       fh;
  ULONG     lfaBase;
  ssDir32 * pDir32Buf;
  ssDir32 * pDir32End;
  ULONG     csOffset;
} XQ_DBG;

/*****************************************************************************/

/** globals - used by other debug data extractors **/

struct exe_hdr  old_hdr;
struct new_exe  new_hdr;
char            szNearestFile[CCHMAXPATH];  /* %s, for current cs:eip   */
char            szNearestLine[16];          /* #%hu, for current cs:eip */
char            szNearestPubDesc[512];      /* %s, for current cs:eip   */
char            szFuncName[256];            /* Last function name read from debug data */
char            szVarName[256];             /* Last variable name read from debug data */

/** struct passed between functions **/

static XQ_DBG   dbgVar;

/* persistent IBM HLL debug info (NB04) data set by PrintLineNum(),
 * and later used by calls to PrintLocalVariables()
*/
static USHORT       userdef_count;
static USHORT       pointer_count;
static ULONG        autovar_count = 0;
static ULONG        ulNearestPubOffset; /* Used for local var matching */
static ULONG        ulSymOffset;        /* Offset of function to match for local variables display */
static char         szSymFuncName[256]; /* Function name at this offset */

static XQ_USERDEF   userdefs[MAX_USERDEFS];
static XQ_POINTERS  pointers[MAX_POINTERS];
static XQ_AUTOVARS  autovars[MAX_AUTOVARS];

/** used by PrintLocalVariables() **/
static BYTE*  type_name[] =
{
  "8 bit signed                ",    /* 0x80 */
  "16 bit signed               ",
  "32 bit signed               ",
  "Unknown (0x83)              ",
  "8 bit unsigned              ",
  "16 bit unsigned             ",
  "32 bit unsigned             ",
  "Unknown (0x87)              ",
  "32 bit real                 ",
  "64 bit real                 ",
  "80 bit real                 ",
  "Unknown (0x8B)              ",
  "64 bit complex              ",
  "128 bit complex             ",
  "160 bit complex             ",
  "Unknown (0x8F)              ",
  "8 bit boolean               ",    /* 0x90 */
  "16 bit boolean              ",
  "32 bit boolean              ",
  "Unknown (0x93)              ",
  "8 bit character             ",
  "16 bit characters           ",
  "32 bit characters           ",
  "void                        ",
  "15 bit unsigned             ",
  "24 bit unsigned             ",
  "31 bit unsigned             ",
  "Unknown (0x9B)              ",
  "Unknown (0x9C)              ",
  "Unknown (0x9D)              ",
  "Unknown (0x9E)              ",
  "Unknown (0x9F)              ",
  "pointer to 8 bit signed     ",    /* 0xa0 */
  "pointer to 16 bit signed    ",
  "pointer to 32 bit signed    ",
  "Unknown (0xA3)              ",
  "pointer to 8 bit unsigned   ",
  "pointer to 16 bit unsigned  ",
  "pointer to 32 bit unsigned  ",
  "Unknown (0xA7)              ",
  "pointer to 32 bit real      ",
  "pointer to 64 bit real      ",
  "pointer to 80 bit real      ",
  "Unknown (0xAB)              ",
  "pointer to 64 bit complex   ",
  "pointer to 128 bit complex  ",
  "pointer to 160 bit complex  ",
  "Unknown (0xAF)              ",
  "pointer to 8 bit boolean    ",    /* 0xb0 */
  "pointer to 16 bit boolean   ",
  "pointer to 32 bit boolean   ",
  "Unknown (0xB3)              ",
  "pointer to 8 bit character  ",
  "pointer to 16 bit character ",
  "pointer to 32 bit character ",
  "pointer to void             ",
  "pointer to 15 bit unsigned  ",
  "pointer to 24 bit unsigned  ",
  "pointer to 31 bit unsigned  ",
  "Unknown (0xBB)              ",
  "Unknown (0xBC)              ",
  "Unknown (0xBD)              ",
  "Unknown (0xBE)              ",
  "Unknown (0xBF)              ",
  "far ptr to 8 bit signed     ",    /* 0xc0 */
  "far ptr to 16 bit signed    ",
  "far ptr to 32 bit signed    ",
  "Unknown (0xC3)              ",
  "far ptr to 8 bit unsigned   ",
  "far ptr to 16 bit unsigned  ",
  "far ptr to 32 bit unsigned  ",
  "Unknown (0xC7)              ",
  "far ptr to 32 bit real      ",
  "far ptr to 64 bit real      ",
  "far ptr to 80 bit real      ",
  "Unknown (0xCB)              ",
  "far ptr to 64 bit complex   ",
  "far ptr to 128 bit complex  ",
  "far ptr to 160 bit complex  ",
  "Unknown (0xCF)              ",
  "far ptr to 8 bit boolean    ",    /* 0xd0 */
  "far ptr to 16 bit boolean   ",
  "far ptr to 32 bit boolean   ",
  "Unknown (0xD3)              ",
  "far ptr to 8 bit character  ",
  "far ptr to 16 bit character ",
  "far ptr to 32 bit character ",
  "far ptr to void             ",
  "far ptr to 15 bit unsigned  ",
  "far ptr to 24 bit unsigned  ",
  "far ptr to 31 bit unsigned  ",    /* 0xda */
};

/*****************************************************************************/

APIRET    PrintLineNum(char* pszFileName, ULONG ulObjNum,
                       ULONG ulOffset, BOOL fSaveSymbols);
BOOL      OpenBinary(XQ_DBG* x);
BOOL      ReadSubsectionDir(XQ_DBG* x);
BOOL      Read32PmDebug(XQ_DBG* x);
ssDir32*  FindModule(XQ_DBG* x);
BOOL      doSSTPUBLICS(XQ_DBG* x, ULONG cbSection);
void      doSSTSYMBOLS(XQ_DBG* x, ULONG cbSection);
void      doSSTTYPES(XQ_DBG* x, ULONG cbSection);
void      doSSTSRCLINES32(XQ_DBG* x, ULONG cbSection);

BOOL      PrintLocalVariables(ULONG ulStackOffset);
BOOL      SearchUserdefs(ULONG stackoffs, USHORT var_no);
BOOL      SearchPointers(ULONG stackoffs, USHORT var_no);
BYTE*     FormatVarValue(PVOID pVar, BYTE type);

/*****************************************************************************/
/*****************************************************************************/
/* Print line number info from embedded debug data or DBG file */

APIRET  PrintLineNum(char* pszFileName, ULONG ulObjNum,
                     ULONG ulOffset, BOOL fSaveSymbols)
{
  XQ_DBG *  x;
  BOOL      ok;

  x = &dbgVar;
  memset(x, 0, sizeof(XQ_DBG));

  x->pszFile = pszFileName;
  x->usSeg = LOUSHORT(ulObjNum) + 1;
  x->ulOffset = ulOffset;
  x->fSaveSymbols = fSaveSymbols;

  /* suppress spurious output from PrintLocalVariables() if this call fails */
  autovar_count = 0;

  /* open the binary (i.e exe or dll) */
  if (!OpenBinary(x))
    return 1;

  if (x->f16Bit)
    return SetupCodeView(x->fh, LOUSHORT(ulObjNum), LOUSHORT(ulOffset), x->pszFile);

  /* try to read the debug directory from the binary */
  ok = ReadSubsectionDir(x);

  /* if that fails, see if there's a .dbg file available */
  if (!ok) {
    close(x->fh);
    strcpy(x->pszFile + strlen(x->pszFile) - 3, "DBG");
    x->fh = sopen(x->pszFile, O_RDONLY | O_BINARY, SH_DENYNO);
    if (x->fh == -1)
      return 1;

    /* try to read the debug directory from the .dbg */
    ok = ReadSubsectionDir(x);
  }

  /* try to extract info for the desired symbol - if successful, print it */
  if (ok) {
    ok = Read32PmDebug(x);
    if (ok)
      fprintf(hTrap, " %s%s %s\n", szNearestFile, szNearestLine, szNearestPubDesc);
  }

  /* clean up */
  close(x->fh);
  if (x->pDir32Buf)
    free(x->pDir32Buf);

  return !ok;
}

/*****************************************************************************/

BOOL    OpenBinary(XQ_DBG* x)
{
  INT  fh;

  fh = sopen(x->pszFile, O_RDONLY | O_BINARY, SH_DENYNO);
  if (fh == -1) {
    fprintf(hTrap, "Can not open %s (%d)\n", x->pszFile, errno);
    return FALSE;
  }

  /* Read old Exe header */
  if (read(fh, &old_hdr, 64) == -1L) {
    fprintf(hTrap, "Can not read old exe header %d\n", errno);
    close(fh);
    return FALSE;
  }

  if (NE_MAGIC(*(struct new_exe*)&old_hdr) == E32MAGIC)
    /* Support stripped LX exes */
    memcpy(&new_hdr, &old_hdr, 64);
  else {
    /* Seek to new Exe header */
    if (lseek(fh, (LONG)E_LFANEW(old_hdr), SEEK_SET) == -1L) {
      fprintf(hTrap, "Can not seek to new exe header %d\n", errno);
      close(fh);
      return FALSE;
    }

    if (read(fh, (PVOID )&new_hdr, 64) == -1L) {
      fprintf(hTrap, "Can not read new exe header %d\n", errno);
      close(fh);
      return FALSE;
    }
  }

  /* Check EXE signature (NE) */
  if (NE_MAGIC(new_hdr) == NEMAGIC) {
    x->fh = fh;
    x->f16Bit = TRUE;
    return TRUE;
  }

  /* Check EXE signature (LX) */
  if (NE_MAGIC(new_hdr) == E32MAGIC) {
    x->fh = fh;
    return TRUE;
  }

  /* Unknown executable */
  fputs("Could not find exe signature", hTrap);
  close(fh);

  return FALSE;
}

/*****************************************************************************/

BOOL    ReadSubsectionDir(XQ_DBG* x)
{
  UINT            cntDir;
  debug_tail_rec  debug_tail;
  debug_head_rec  debug_head;

  if (lseek(x->fh, -8L, SEEK_END) == -1) {
    fprintf(hTrap, "Can not seek SEEK_END - 8 %s (%d)\n",
            x->pszFile, errno);
    return FALSE;
  }

  if (read(x->fh, &debug_tail, 8) == -1) {
    fprintf(hTrap, "Can not read debug sig from %s (%d)\n",
            x->pszFile, errno);
    return FALSE;
  }

  if (debug_tail.signature != HLLDBG_SIG) {
    /* fputs("\nNo HLL debug data stored.\n", hTrap); */
    return FALSE;
  }

  if ((x->lfaBase = lseek(x->fh, -debug_tail.offset, SEEK_END)) == -1L) {
    fprintf(hTrap, "Can not seek to debug data tail in %s (%d)\n",
            x->pszFile, errno);
    return FALSE;
  }

  if (read(x->fh, &debug_head, 8) == -1) {
    fprintf(hTrap, "Error %u reading HLL debug data header in %s\n",
            errno, x->pszFile);
    return FALSE;
  }

  /* 27 May 08 SHL fixme to read entire hll_dirinfo header */
  if (lseek(x->fh, debug_head.lfoDir - 8 + 4, SEEK_CUR) == -1) {
    fprintf(hTrap, "Error %u seeking to HLL debug data directory in %s\n",
            errno, x->pszFile);
    return FALSE;
  }

  if (read(x->fh, &cntDir, 4) == -1) {
    fprintf(hTrap, "Error %u reading HLL debug data directory count in %s\n",
            errno, x->pszFile);
    return FALSE;
  }

  /* Allocate buffer to hold subsection directory table */
  x->pDir32Buf = (ssDir32*)calloc(cntDir, sizeof(ssDir32));
  if (!x->pDir32Buf) {
    fputs("Out of memory!", hTrap);
    return FALSE;
  }

  /* Read subsection directory into buffer */
  if (read(x->fh, x->pDir32Buf, cntDir * sizeof(ssDir32)) == -1) {
    fprintf(hTrap, "Error %u reading HLL debug data directory from %s\n",
            errno, x->pszFile);
    free(x->pDir32Buf);
    return FALSE;
  }

  x->pDir32End = &x->pDir32Buf[cntDir];

  return TRUE;
}

/*****************************************************************************/

BOOL    Read32PmDebug(XQ_DBG* x)
{
  ssDir32 * pDir;
  BOOL      read_types = FALSE;

  /* clear the persistent variables used to
   * store data for PrintLocalVariables() */
  userdef_count = 0;
  pointer_count = 0;
  autovar_count = 0;
  ulNearestPubOffset = 0;
  ulSymOffset = 0;
  *szSymFuncName = 0;
  *szNearestPubDesc = 0;
  *szNearestLine = 0;
  *szNearestFile = 0;

  pDir = FindModule(x);
  if (!pDir)
    return FALSE;

  /* step thru the entries for this module */
  for (; pDir < x->pDir32End; pDir++) {

    /* Skip the SSTMODULES entry */
    if (pDir->sst == SSTMODULES)
      continue;

    /* Position to subsection */
    if (lseek(x->fh, pDir->lfoStart + x->lfaBase, SEEK_SET) == -1) {
      fprintf(hTrap, "Error %u seeking data in %s\n", errno, x->pszFile);
      return FALSE;
    }

    switch (pDir->sst) {

      case SSTPUBLICS:
        read_types = doSSTPUBLICS(x, pDir->cb);
        break;

      /* Read symbols, so we can dump the auto variables on the stack */
      case SSTSYMBOLS:
        if (x->fSaveSymbols)
          doSSTSYMBOLS(x, pDir->cb);
        break;

      case SSTTYPES:
        if (x->fSaveSymbols && read_types)
          doSSTTYPES(x, pDir->cb);
        break;

      case SSTSRCLINES32:
        doSSTSRCLINES32(x, pDir->cb);
        break;
#if 0
      default:
        fprintf(hTrap, "HLL type %u unknown%s\n", pDir->sst);
#endif
    } /* switch sst */
  } /* for pDir < x->pDirEnd */

  return TRUE;
}

/*****************************************************************************/

ssDir32*  FindModule(XQ_DBG* x)
{
  ssDir32 *   pDir;
  ssDir32 *   pDirStart;
  USHORT      modNbr;
  USHORT      ctr = 0;
  ssModule32  ssmod32;

  modNbr = (USHORT)-1;

  for (pDir = x->pDir32Buf; pDir < x->pDir32End; pDir++, ctr++) {

    /* new module - save the starting address */
    if (pDir->modindex != modNbr) {
      pDirStart = pDir;
      modNbr = pDir->modindex;
    }

    /* if this isn't an SSTMODULES entry, skip it */
    if (pDir->sst != SSTMODULES)
      continue;

    /* Seek to module header then read it */
    lseek(x->fh, pDir->lfoStart + x->lfaBase, SEEK_SET);
    read(x->fh, &ssmod32.csBase, sizeof(ssModule32));

    /* wrong seg */
    if (ssmod32.csBase != x->usSeg)
      continue;

    /* found the module we need - get its name, then exit loop */
    if (x->ulOffset >= ssmod32.csOff && x->ulOffset < ssmod32.csOff + ssmod32.csLen) {
      x->csOffset = ssmod32.csOff;
      read(x->fh, szModName, (unsigned)ssmod32.csize);
      szModName[ssmod32.csize] = 0;
      break;
    }
  }

  /* didn't find the seg & offset, so exit */
  if (pDir >= x->pDir32End)
    return 0;

  /* get the address to stop at, i.e the first entry for the next module */
  for ( ; pDir < x->pDir32End; pDir++) {
    if (pDir->modindex != modNbr)
      break;
  }
  x->pDir32End = pDir;

  return pDirStart;
}

/*****************************************************************************/

BOOL    doSSTPUBLICS(XQ_DBG* x, ULONG cbSection)
{
  int         nBytesRead = 0;
  long        filePos;
  ULONG       nearestOffs = 0;
  ULONG       nearestPos = 0;
  ssPublic32  sspub32;

  /* remember the starting pos */
  filePos = tell(x->fh);

  /* entries are not in order, so read every one looking for
   * the nearest;  if there's an exact match, exit early
   */
  while (nBytesRead < cbSection) {

    if (read(x->fh, &sspub32.offset, sizeof(sspub32)) == -1) {
      fprintf(hTrap, "Error %u reading data in %s\n", errno, x->pszFile);
      return FALSE;
    }
    if (lseek(x->fh, sspub32.csize, SEEK_CUR) == -1) {
      fprintf(hTrap, "Error %u seeking data in %s\n", errno, x->pszFile);
      return FALSE;
    }

    if (sspub32.segment == x->usSeg &&
        sspub32.offset >= nearestOffs &&
        sspub32.offset <= x->ulOffset) {
      nearestOffs = sspub32.offset;
      nearestPos  = nBytesRead;
      if (sspub32.offset == x->ulOffset)
        break;
    }

    nBytesRead += sizeof(sspub32) + sspub32.csize;
  }

  /* seek back to the nearest entry, then read it */
  if (lseek(x->fh, filePos + nearestPos, SEEK_SET) == -1) {
      fprintf(hTrap, "Error %u seeking data in %s\n", errno, x->pszFile);
      return FALSE;
  }
  read(x->fh, &sspub32.offset, sizeof(sspub32));
  read(x->fh, szFuncName, (unsigned)sspub32.csize);
  szFuncName[sspub32.csize] = 0;

  /* remember the offset for local var matching, then format the description */
  ulNearestPubOffset = sspub32.offset;
  sprintf(szNearestPubDesc, "%s%s %04X:%08X (%s)",
          sspub32.type == 1 ? "Abs " : "", szFuncName,
          sspub32.segment, sspub32.offset, szModName);

  return TRUE;
}

/*****************************************************************************/

void    doSSTSYMBOLS(XQ_DBG* x, ULONG cbSection)
{
  INT         nBytesRead;
  ULONG       ulFileOffset;
  UINT        CurrSymSeg = 0;
  BOOL        dump_vars = FALSE;
  USHORT      usLength;
  USHORT      usSize;
  BYTE        b1;
  BYTE        b2;
  BYTE        bType;
  symseg_rec  symseg;
  symauto_rec symauto;
  symproc_rec symproc;

  nBytesRead = 0;
  while (nBytesRead < cbSection) {

    /* Read encoded length of this subentry */
    nBytesRead += read(x->fh, &b1, 1);
    if (b1 & 0x80) {
      nBytesRead += read(x->fh, &b2, 1);
      usLength = ((b1 & 0x7F) << 8) + b2;
    }
    else
      usLength = b1;

    ulFileOffset = tell(x->fh);
    nBytesRead += read(x->fh, &bType, 1);

    switch (bType) {
      case SYM_CHANGESEG:
        read(x->fh, &symseg, sizeof(symseg));
        CurrSymSeg = symseg.seg_no;
        break;

      case SYM_MEMFUNC:
      case SYM_PROC:
      case SYM_CPPPROC:
        if (dump_vars)
          return;

        dump_vars = FALSE;
        read(x->fh, &symproc, sizeof(symproc));

        if (CurrSymSeg == x->usSeg &&
            x->ulOffset >= symproc.offset &&
            x->ulOffset < symproc.offset + symproc.length) {
          /* Got function name, try to find locals */
          dump_vars = TRUE;
          autovar_count = 0;
          ulSymOffset = symproc.offset;

          read(x->fh, szSymFuncName, symproc.name_len);
          szSymFuncName[symproc.name_len] = 0;
        }

        break;

      case SYM_AUTO:
        if (!dump_vars)
          break;
        if (autovar_count >= MAX_AUTOVARS)
          return;

        read(x->fh, &symauto, sizeof(symauto));

        usSize = (symauto.name_len > MAX_AUTONAMBYTES - 1 ?
                  MAX_AUTONAMBYTES - 1 : symauto.name_len);
        read(x->fh, autovars[autovar_count].name, usSize);
        autovars[autovar_count].name[usSize] = 0;

        autovars[autovar_count].stack_offset = symauto.stack_offset;
        autovars[autovar_count].type_idx = symauto.type_idx;
        autovar_count++;

        break;

      default:  
        /* fprintf(stderr, "SYM_UNKNOWN - type= %hx\n", (USHORT)bType); */
        break;

    } /* switch bType */

    nBytesRead += usLength;

    /* Position to next symbol record */
    lseek(x->fh, ulFileOffset + usLength, SEEK_SET);

  } /* while */

  return;
}

/*****************************************************************************/

void    doSSTTYPES(XQ_DBG* x, ULONG cbSection)
{
  INT         nBytesRead;
  ULONG       ulFileOffset;
  USHORT      idx;
  type_rec    type;
  type_userdefrec udef;
  type_pointerrec point;

  nBytesRead = 0;
  idx = 0x200;
  userdef_count = 0;
  pointer_count = 0;
  while (nBytesRead < cbSection) {

    /* Remember current file offset */
    ulFileOffset = tell(x->fh);

    /* Read the length of this subentry */
    read(x->fh, &type, sizeof(type));
    nBytesRead += sizeof(type);

    switch (type.type) {
      case TYPE_USERDEF:
        if (userdef_count >= MAX_USERDEFS)
          break;

        read(x->fh, &udef, sizeof(udef));
        read(x->fh, szVarName, udef.name_len);
        szVarName[udef.name_len] = 0;

        /* Insert userdef in table */
        userdefs[userdef_count].idx = idx;
        userdefs[userdef_count].type_index = udef.type_index;
        memcpy(userdefs[userdef_count].name,
               szVarName, min(udef.name_len + 1, 32));
        userdefs[userdef_count].name[32] = 0;
        userdef_count++;
        break;

      case TYPE_POINTER:
        if (pointer_count >= MAX_POINTERS)
          break;

        read(x->fh, &point, sizeof(point));
        read(x->fh, szVarName, point.name_len);
        szVarName[point.name_len] = 0;

        /* Insert pointer def in table */
        pointers[pointer_count].idx = idx;
        pointers[pointer_count].type_index = point.type_index;
        memcpy(pointers[pointer_count].name,
               szVarName, min(point.name_len + 1, 32));
        pointers[pointer_count].name[32] = 0;
        pointers[pointer_count].type_qual = type.type_qual;
        pointer_count++;
        break;
    } /* switch type.type */

    ++idx;
    nBytesRead += type.length;
    lseek(x->fh, ulFileOffset + type.length + 2, SEEK_SET);

  } /* while */

  return;
}

/*****************************************************************************/

void    doSSTSRCLINES32(XQ_DBG* x, ULONG cbSection)
{
  INT           nBytesRead;
  ULONG         ul;
  ULONG         ulFileOffset;
  UINT          NearestFile = 0;
  UINT          NearestLine = 0;
  UINT          uNdx;
  char *        psz;
  ssLineEntry32 LineEntry;
  ssFileNum32         FileInfo;
  ssFirstLineEntry32  FirstLine;


  /* find first type 0 line number record
   * skip leading type 3 pszFileName list records
   */
  ulFileOffset = 0;

  do {
    read(x->fh, &FirstLine, sizeof(FirstLine));

    if (FirstLine.LineNum != 0) {
      fputs("Missing Line table information\n", hTrap);
      FirstLine.numlines = 0;
      break;
    }

    /* If type 0..3, read rest of header
     * Type 4 omits length/seg_address field
     */
    if (FirstLine.entry_type < 4) {
      read(x->fh, &ul, 4);
      /* If type 3, remember start of file names table and position after */
      if (FirstLine.entry_type == 3) {
        if (!ulFileOffset)
          ulFileOffset = tell(x->fh);
        lseek(x->fh, ul, SEEK_CUR);
      }
    }

  } while (FirstLine.entry_type == 3);

  for (uNdx = 0; uNdx < FirstLine.numlines; uNdx++) {
    switch (FirstLine.entry_type) {
      case LINEREC_SRC_LINES:
        read(x->fh, &LineEntry, sizeof(LineEntry));
        if (LineEntry.LineNum &&
            LineEntry.ulOffset + x->csOffset >= NearestLine &&
            LineEntry.ulOffset + x->csOffset <= x->ulOffset) {
          /* Found better match */
          NearestLine = LineEntry.ulOffset;
          NearestFile = LineEntry.FileNum;
          sprintf(szNearestLine, "#%hu", LineEntry.LineNum);
        }
        break;

      case LINEREC_LIST_LINES:
        lseek(x->fh, sizeof(linlist_rec), SEEK_CUR);
        break;

      case LINEREC_SRCLIST_LINES:
        lseek(x->fh, sizeof(linsourcelist_rec), SEEK_CUR);
        break;

      case LINEREC_FILENAMES:
        lseek(x->fh, sizeof(filenam_rec), SEEK_CUR);
        break;

      case LINEREC_PATHINFO:
        lseek(x->fh, sizeof(pathtab_rec), SEEK_CUR);
        break;
    } /* switch FirstLine.entry_type */

  } /* for */

  if (!NearestFile)
    *szNearestFile = 0;
  else {
    /* Have filename index, find name - lseek back to filenames entry */
    lseek(x->fh, ulFileOffset, SEEK_SET);
    read(x->fh, &FileInfo, sizeof(FileInfo));
    ul = 0;

    for (uNdx = 1; uNdx <= FileInfo.file_count; uNdx++) {
      ul = 0;
      read(x->fh, &ul, 1);
      read(x->fh, szNearestFile, ul);
      if (uNdx == NearestFile)
        break;
    }

    szNearestFile[ul] = 0;
    psz = strrchr(szNearestFile, '\\');
    if (psz)
      strcpy(szNearestFile, psz + 1);
  }

  return;
}

/*****************************************************************************/
/*****************************************************************************/
/* Print local variable values from data
 * stored by a previous call to PrintLineNum() */

BOOL    PrintLocalVariables(ULONG ulStackOffset)
{
  USHORT  n;

  if (ulSymOffset != ulNearestPubOffset || !autovar_count)
    return FALSE;

/*
   fprintf(hTrap, "  Auto variables for %s at EBP %p:\n",
           szSymFuncName, ulStackOffset);
*/
   fputs("  Offset Name                 Type                         Hex Value\n"
         "  컴컴컴 컴컴컴컴컴컴컴컴컴컴 컴컴컴컴컴컴컴컴컴컴컴컴컴컴 컴컴컴컴�\n", hTrap);

  /* Found locals for this function */
  for (n = 0; n < autovar_count; n++) {

    /* If it's one of the simple types */
    if (autovars[n].type_idx >= 0x80 && autovars[n].type_idx <= 0xDA) {
      fprintf(hTrap, "  %- 6d %- 20.20s %- 28.28s %s\n",
              autovars[n].stack_offset,
              autovars[n].name,
              type_name[autovars[n].type_idx - 0x80],
              FormatVarValue((PVOID)(ulStackOffset + autovars[n].stack_offset),
                             autovars[n].type_idx - 0x80));
    }
    else
    /* Complex type, check if we know what it is */
    if (!SearchUserdefs(ulStackOffset, n) &&
        !SearchPointers(ulStackOffset, n)) {
      sprintf(szBuffer, "0x%X", autovars[n].type_idx);
      fprintf(hTrap, "  %- 6d %-20.20s %- 28.28s %X\n",
              autovars[n].stack_offset,
              autovars[n].name,
              szBuffer,
              *(ULONG*)(ulStackOffset + autovars[n].stack_offset));
    }
  }

  return TRUE;
}

/*****************************************************************************/
/* Search saved user type definitions and print values if matched
 * @return TRUE if matched else FALSE
 */

BOOL    SearchUserdefs(ULONG stackoffs, USHORT var_no)
{
  USHORT  pos;

  for (pos = 0;
       pos < userdef_count && userdefs[pos].idx != autovars[var_no].type_idx;
       pos++)
    ; /* do nothing */

  /* If the result isn't a simple type, let's act as we didn't find it */
  if (pos >= userdef_count ||
      userdefs[pos].type_index < 0x80 &&
      userdefs[pos].type_index > 0xDA)
    return FALSE;

  fprintf(hTrap, "  %- 6d %- 20.20s %- 28.28s %s\n",
          autovars[var_no].stack_offset,
          autovars[var_no].name,
          userdefs[pos].name,
          FormatVarValue((PVOID)(stackoffs + autovars[var_no].stack_offset),
                         userdefs[pos].type_index - 0x80));

  return TRUE;
}

/*****************************************************************************/
/* Search saved pointer definitions and print values if matched
 * @return TRUE if matched else FALSE
 */

BOOL    SearchPointers(ULONG stackoffs, USHORT var_no)
{
  USHORT  pos;
  USHORT  upos;
  static BYTE str[35];

  for (pos = 0;
       pos < pointer_count && pointers[pos].idx != autovars[var_no].type_idx;
       pos++)
    ; /* do nothing */

  if (pos >= pointer_count)
    return FALSE;

  /* Found it */
  if (pointers[pos].type_index >= 0x80 && pointers[pos].type_index <= 0xDA) {
    strcpy(str, type_name[pointers[pos].type_index - 0x80]);
    strcat(str, " *");
    fprintf(hTrap, "  %- 6d %- 20.20s %- 28.28s %s\n",
            autovars[var_no].stack_offset,
            autovars[var_no].name,
            str,
            FormatVarValue((PVOID)(stackoffs + autovars[var_no].stack_offset), 32));
    return TRUE;
  }

  /* If the result isn't a simple type, look for it in the other lists */
  for (upos = 0;
       upos < userdef_count && userdefs[upos].idx != pointers[pos].type_index;
       upos++)
    ; /* do nothing */

  if (upos < userdef_count) {
    strcpy(str, userdefs[upos].name);
    strcat(str, " *");
    fprintf(hTrap, "  %- 6d %- 20.20s %- 28.28s %s\n",
            autovars[var_no].stack_offset,
            autovars[var_no].name,
            str,
            FormatVarValue((PVOID)(stackoffs + autovars[var_no].stack_offset), 32));
    return TRUE;
  }

  /* If it isn't a userdef, for now give up and just print as much as we know */
  sprintf(str, "pointer to type 0x%X", pointers[pos].type_index);
  fprintf(hTrap, "  %- 6d %- 20.20s %- 28.28s %s\n",
          autovars[var_no].stack_offset,
          autovars[var_no].name,
          str,
          FormatVarValue((PVOID)(stackoffs + autovars[var_no].stack_offset), 32));

  return TRUE;
}

/*****************************************************************************/

/* Format variable value, return string */

BYTE*   FormatVarValue(PVOID pVar, BYTE type)
{
  APIRET  rc;
  ULONG   ulAttr;
  ULONG   ulSize;

  switch (type) {
    case 0:
      sprintf(szBuffer, "%hX", *(signed char *)pVar);
      break;
    case 1:
      sprintf(szBuffer, "%hX", *(signed short *)pVar);
      break;
    case 2:
      sprintf(szBuffer, "%lX", *(signed long *)pVar);
      break;
    case 4:
      sprintf(szBuffer, "%hX", *(BYTE *)pVar);
      break;
    case 5:
      sprintf(szBuffer, "%hX", *(USHORT *)pVar);
      break;
    case 6:
      sprintf(szBuffer, "%lX", *(ULONG *)pVar);
      break;
    case 8:
      sprintf(szBuffer, "%f", *(float *)pVar);
      break;
    case 9:
      sprintf(szBuffer, "%f", *(double *)pVar);
      break;
    case 10:
      sprintf(szBuffer, "%f", *(long double *)pVar);
      break;
    case 16:
      sprintf(szBuffer, "%s", *(char *)pVar ? "TRUE" : "FALSE");
      break;
    case 17:
      sprintf(szBuffer, "%s", *(short *)pVar ? "TRUE" : "FALSE");
      break;
    case 18:
      sprintf(szBuffer, "%s", *(long *)pVar ? "TRUE" : "FALSE");
      break;
    case 20:
      sprintf(szBuffer, "%c", *(char *)pVar);
      break;
    case 21:
      sprintf(szBuffer, "%lc", *(short *)pVar);
      break;
    case 22:
      sprintf(szBuffer, "%lc", *(long *)pVar);
      break;
    case 23:
      sprintf(szBuffer, "void");
      break;
    default:
      if (type < 32) {
        strcpy(szBuffer, "Unknown");
        break;
      }

      ulSize = 1;
      rc = DosQueryMem(pVar, &ulSize, &ulAttr);
      if (rc) {
        sprintf(szBuffer, "%p invalid", *(ULONG *)pVar);
        break;
      }

      sprintf(szBuffer, "%p", *(ULONG *)pVar);
      if (ulAttr & PAG_FREE)
        strcat(szBuffer, " unallocated memory");
      else {
        if (~ulAttr & PAG_COMMIT)
          strcat(szBuffer, " uncommited");
        if (~ulAttr & PAG_WRITE)
          strcat(szBuffer, " unwritable");
        if (~ulAttr & PAG_READ)
          strcat(szBuffer, " unreadable");
      }
      break;
  }

  return szBuffer;
}

/*****************************************************************************/
/*****************************************************************************/

