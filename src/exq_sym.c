/*****************************************************************************/
/*
 *  exq_sym.c - symbol file parser (.sym & .xqs)
 *
 *  Parts of this file are
 *    Copyright (c) 2000-2010 Steven Levine and Associates, Inc.
 *    Copyright (c) 2010-2011 Richard L Walsh
 *
*/
/*****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define INCL_DOS
#define INCL_DOSERRORS
#include <os2.h>

#include "sym.h"
#include "xqs.h"
#include "exq.h"

/*****************************************************************************/

/** defines **/

#define SYMFILE_CNT 16
#define SYMBUF_SIZE 4096
#define SYMPTR_CNT  512

/** typedefs **/

typedef struct _SYMFILE
{
  HMODULE   hMod;
  ULONG     seg;
  ULONG     lru;
  FILE*     fSym;
  ULONG     cbFile;
  ULONG     maxSymLth;
  ULONG     cntSyms;
  ULONG     offsThisSeg;
  ULONG     offsSymPtr;
  ULONG     cbXQSYM;
  USHORT    segFlags;
  USHORT    sfFlags;
  char*     pBuffer;
} SYMFILE;

#define SYMFILE_MULTIUSE  1
#define SYMFILE_XQS       2

typedef struct _SYMVAR
{
  ULONG     targetAddr;
  ULONG     lastAddr;
  ULONG     offsSymPtr;
  char *    pSymDef;
  char *    pText;
  char *    pSymPtrBuf;
} SYMVAR;

/*****************************************************************************/

/** static data */

static SYMVAR   symVar;
static SYMFILE  asf[SYMFILE_CNT];
static char     symBuffer[SYMBUF_SIZE];

/*****************************************************************************/

void    PrintSymbolFromFile(char * pszFile, HMODULE hMod,
                            ULONG ulObjNum, ULONG ulOffset);

void    SymPrintSymbol(SYMFILE* psf, ULONG ulOffset);
BOOL    Sym32(SYMFILE* psf, SYMVAR* pvar);
BOOL    Sym16(SYMFILE* psf, SYMVAR* pvar);

void    XqsPrintSymbol(SYMFILE* psf, ULONG ulOffset);
BOOL    XqsReadName(FILE* fSym, char* pText, XQSYM* pSym);
BOOL    XqsReadMod(FILE* fSym, char* pText, XQSYM* pSym);

SYMFILE* InitSymbolFile(ULONG ulSeg, HMODULE hMod, char* pszFile);
BOOL    OpenSymbolFile(SYMFILE* psf, char* pszFile);
BOOL    SymFindSegment(SYMFILE* psf);
ULONG   SymGetNextSegment(SYMFILE* psf, ULONG offsSeg, SEGDEF* psd);
BOOL    XqsFindSegment(SYMFILE* psf);
void    CloseSymbolFiles(void);

/*****************************************************************************/
/*  Symbol File handler                                                      */
/*****************************************************************************/

void    PrintSymbolFromFile(char * pszFile, HMODULE hMod,
                            ULONG ulObjNum, ULONG ulOffset)
{
  SYMFILE*  psf;

  TimedBeep();

  /* Get a ptr to a SYMFILE struct containing info needed to
   * step through the symbols for the requested segment.
   */
  psf = InitSymbolFile(++ulObjNum, hMod, pszFile);

  if (psf) {
    if (psf->sfFlags & SYMFILE_XQS)
      XqsPrintSymbol(psf, ulOffset);
    else
      SymPrintSymbol(psf, ulOffset);
  }

  fputc('\n', hTrap);
  return;
}

/*****************************************************************************/
/*  SYM File handler                                                         */
/*****************************************************************************/

/* 23 May 08 SHL Add oversized .sym file support
 * Symbol table format uses 16-bit offsets to point at the symbol
 * pointer table and to point at SymDef entries.  This breaks if there
 * are more than approx 64KiB of SymDefs.  To workaround this,
 * we assume that the symbol pointer table ends at the next SegDef
 * or at the end of file.  We then use the difference between the
 * calculated offset of the end of the pointer table and the calculated
 * offset to the next SegDef to calculate an adjusting offset.
 * This offset is applied to symbol pointer table lookups.
 * We also assume that the SymDef offsets in the symbol pointer table
 * are monotonic and detect 64KiB boundary crossings to calculate an
 * adjusting offset.  This offset is applied to SymDef entry indexing.
 */

void    SymPrintSymbol(SYMFILE* psf, ULONG ulOffset)
{
  ULONG     ctr;
  ULONG     size;
  ULONG     offset;
  ULONG     SymDef;
  ULONG     SymDefLo;
  ULONG     SymDefHi;
  ULONG     SymPtrAdjust;
  ULONG     SymPtrLast;
  USHORT*   pSymPtr;
  SYMVAR*   pvar;

  SymDefLo = 0xffffffff;
  SymDefHi = 0;
  SymPtrAdjust = 0;
  SymPtrLast = 0;

  /* Init a SYMVAR struct to (minimally) reduce stack usage. */
  pvar = &symVar;
  memset(pvar, 0, sizeof(SYMVAR));
  pvar->targetAddr = ulOffset;
  pvar->offsSymPtr = psf->offsSymPtr;
  pvar->pText = szBuffer;
  pvar->pSymPtrBuf = bigBuf;

  /* Put something in the buffer in case there's no symbol at offset 0 */
  strcpy(pvar->pText, "[start]");

  /* Step through each entry in the symbol pointer table
   * until we reach or pass the requested offset.
   */
  for (ctr = 0; ctr < psf->cntSyms; ctr++, pSymPtr++) {

    TimedBeep();

    /* Cache a maximum of SYMPTR_CNT entries from the symbol ptr table.
     * This makes a huge improvement in performance by vastly reducing
     * the number of seeks required for large symfiles.
     */
    if (!(ctr & (SYMPTR_CNT - 1))) {
      if (fseek(psf->fSym, pvar->offsSymPtr, SEEK_SET)) {
        fprintf(hTrap, " SymDef seek error at %x ", pvar->offsSymPtr);
        break;
      }

      size = psf->cntSyms - ctr;
      if (size > SYMPTR_CNT)
        size = SYMPTR_CNT;
      size *= sizeof(USHORT);

      if (fread(pvar->pSymPtrBuf, size, 1, psf->fSym) != 1) {
        fprintf(hTrap, " SymDef read error at %x ", pvar->offsSymPtr);
        break;
      }

      pvar->offsSymPtr += size;
      pSymPtr = (USHORT*)pvar->pSymPtrBuf;
    }

    /* If symbol entries crossed a 64K boundary, inc the offset adjustment. */
    if (*pSymPtr < SymPtrLast)
      SymPtrAdjust += 0x10000;
    SymPtrLast = *pSymPtr;

    /* Calc the offset of the next SymDef (relative to the seg's start). */
    SymDef = *pSymPtr + SymPtrAdjust;

    /* If the desired offset isn't within the SymDef cache, seek to that
     * offset in the file and refill the cache.  To avoid having to check
     * each SymDef16/32 to ensure it lies entirely within the cache, set
     * SymDefHi to an offset that could contain the largest possible SymDef.
     * Like the SymPtr cache, this cache produces a huge performance gain.
     */
    if (SymDef < SymDefLo || SymDef > SymDefHi) {
      SymDefLo = SymDef;

      /* Convert from a seg-relative to a file-relative offset. */
      offset = SymDefLo + psf->offsThisSeg;
      if (fseek(psf->fSym, offset, SEEK_SET)) {
        fprintf(hTrap, " SymDef seek error at %lx ", offset);
        break;
      }

      /* Read the lesser of SYMBUF_SIZE bytes or the remaining SymDefs. */
      size = psf->offsSymPtr - SymDefLo;
      if (size > SYMBUF_SIZE) {
        size = SYMBUF_SIZE;
        SymDefHi = SymDefLo + size - (sizeof(SYMDEF32) + psf->maxSymLth);
      }
      else
        SymDefHi = SymDefLo + size - sizeof(SYMDEF32);

      if (fread(psf->pBuffer, 1, size, psf->fSym) < size) {
        fprintf(hTrap, " SymDef16/32 read error - %lx bytes at %lx ",
                size, offset);
        break;
      }
    }

    /* Calc the address within the cache where the desired SymDef lies. */
    pvar->pSymDef = &psf->pBuffer[SymDef - SymDefLo];

    /* Call the function that will determine if we've reached or exceeded
     * the desired offset.  If so, it will print out the data & return TRUE.
     * If not, it will store some info and return FALSE.
     */
    if (psf->segFlags & 0x01) {
      if (Sym32(psf, pvar))
        break;
    }
    else {
      if (Sym16(psf, pvar))
        break;
    }

    /* Special case for the last symbol in the table. */
    if (ctr + 1 == psf->cntSyms) {
      if (pvar->targetAddr >= pvar->lastAddr && *pvar->pText) {
        if (pvar->targetAddr == pvar->lastAddr)
          fprintf(hTrap, " %s (%X)", pvar->pText, pvar->targetAddr);
        else
          fprintf(hTrap, " near %s + %X ", pvar->pText, pvar->targetAddr - pvar->lastAddr);
      }
    }
  } /* for symbols */

  return;
}

/*****************************************************************************/

BOOL    Sym32(SYMFILE* psf, SYMVAR* pvar)
{
  ULONG     ul;
  SYMDEF32* psd32;

  psd32 = (SYMDEF32*)pvar->pSymDef;

  /* If the requested offset is GTE the previous symbol offset
   * and LT the current symbol offset, then it's time to display.
   */
  ul = pvar->targetAddr >= pvar->lastAddr && pvar->targetAddr < psd32->wSymVal;
  if (ul) {

    if (pvar->targetAddr == pvar->lastAddr) {
      fprintf(hTrap, " %s", pvar->pText);
      return TRUE;
    }

    fprintf(hTrap, " between %s + %X ",
            pvar->pText, pvar->targetAddr - pvar->lastAddr);
  }

  /* Remember symbol and offset */
  pvar->lastAddr = psd32->wSymVal;

  memcpy(pvar->pText, psd32->achSymName, psd32->cbSymName);
  pvar->pText[psd32->cbSymName] = 0;

  /* Display if requested offset is between symbols or at symbol. */
  if (ul) {
    fprintf(hTrap, "and %s - %X",
            pvar->pText, pvar->lastAddr - pvar->targetAddr);
    return TRUE;
  }

  return FALSE;
}

/*****************************************************************************/

BOOL    Sym16(SYMFILE* psf, SYMVAR* pvar)
{
  ULONG     ul;
  SYMDEF16* psd16;

  psd16 = (SYMDEF16*)pvar->pSymDef;

  /* If the requested offset is GTE the previous symbol offset
   * and LT the current symbol offset, then it's time to display.
   */
  ul = pvar->targetAddr >= pvar->lastAddr && pvar->targetAddr < psd16->wSymVal;
  if (ul) {

    if (pvar->targetAddr == pvar->lastAddr) {
      fprintf(hTrap, " %s", pvar->pText);
      return TRUE;
    }

    fprintf(hTrap, " between %s + %X ", pvar->pText, pvar->targetAddr - pvar->lastAddr);
  }

  /* Remember symbol and offset */
  pvar->lastAddr = psd16->wSymVal;

  memcpy(pvar->pText, psd16->achSymName, psd16->cbSymName);
  pvar->pText[psd16->cbSymName] = 0;

  /* Display if requested offset is between symbols or at symbol. */
  if (ul) {
    fprintf(hTrap, "and %s - %X", pvar->pText, pvar->lastAddr - pvar->targetAddr);
    return TRUE;
  }

  return FALSE;
}

/*****************************************************************************/
/*  XQS File handler                                                         */
/*****************************************************************************/

void    XqsPrintSymbol(SYMFILE* psf, ULONG ulOffset)
{
  BOOL      fModInfo;
  ULONG     readCnt;
  ULONG   	curCnt;
  ULONG   	cbSym;
  XQSYM *   pSym;
  XQSYM *   pLast;
  static XQSYM  xqsSave;

  TimedBeep();

  /* Exit if nothing to do. */
  if (!psf->cntSyms)
    return;

  /* Seek to the first XQSYM entry for this segment. */
  if (fseek(psf->fSym, psf->offsSymPtr, SEEK_SET)) {
    fprintf(hTrap, " Can not seek to XQSYM at %x", psf->offsSymPtr);
    return;
  }

  memset(&xqsSave, 0, sizeof(xqsSave));
  readCnt = 0;

  /* Module info isn't present if cbSym is less than 16 bytes. */
  cbSym   = psf->cbXQSYM;
  fModInfo = (cbSym >= XQS_SYMSIZE_MOD);

  /* Read blocks of XQSYM entries looking for a block whose
   * last entry has an address GTE the one we're looking for.
   */
  curCnt = psf->cntSyms;
  while (curCnt) {

    /* Read as many XQSYM entries as will fit in the buffer. */
    readCnt = SYMBUF_SIZE / cbSym;
    if (readCnt > curCnt)
      readCnt = curCnt;

    if (fread(psf->pBuffer, cbSym, readCnt, psf->fSym) != readCnt) {
      fprintf(hTrap, " Can not read %ld XQSYMs at %x",
              readCnt, ftell(psf->fSym));
      return;
    }

    /* Point at the last entry & see if it's GTE our target. */
    pSym = (XQSYM*)(psf->pBuffer + (readCnt-1) * cbSym);
    if (pSym->address >= ulOffset)
      break;

    /* If not, save it in case we need it below. */
    memcpy(&xqsSave, pSym, cbSym);
    curCnt -= readCnt;
  }

  /* no symbol had an address >= ulOffset - use the very last entry */
  if (!curCnt) {
    fprintf(hTrap, " %s + %X",
            XqsReadName(psf->fSym, szBuffer, &xqsSave) ? szBuffer : "[error]",
            ulOffset - xqsSave.address);
    if (fModInfo && xqsSave.offsMod)
      fprintf(hTrap, "  (in %s)",
              XqsReadMod(psf->fSym, szBuffer, &xqsSave) ?  szBuffer : "[n/a]");
    return;
  }

  /* scan the block for an address >= the target */
  pLast = &xqsSave;
  for (curCnt = 0, pSym = (XQSYM*)psf->pBuffer;
       curCnt < readCnt;
       curCnt++, pSym = (XQSYM*)((char*)pSym + cbSym)) {
    if (pSym->address >= ulOffset)
      break;

    pLast = pSym;
  }
  /* this shouldn't happen */
  if (curCnt >= readCnt)
    return;

  /* ulOffset matches a specific symbol */
  if (pSym->address == ulOffset) {
      fprintf(hTrap, " %s",
              XqsReadName(psf->fSym, szBuffer, pSym) ? szBuffer : "[error]");
    if (fModInfo && pSym->offsMod)
      fprintf(hTrap, "  (in %s)",
              XqsReadMod(psf->fSym, szBuffer, pSym) ?  szBuffer : "[n/a]");
    return;
  }

  /* ulOffset lies between two symbols */
  fprintf(hTrap, " between %s + %X and %s - %X",
          XqsReadName(psf->fSym, szBuffer, pLast) ? szBuffer : "[error]",
          ulOffset - pLast->address,
          XqsReadName(psf->fSym, bigBuf, pSym) ? bigBuf : "[error]",
          pSym->address - ulOffset);

  if (fModInfo) {
    if (pLast->offsMod == pSym->offsMod) {
      if (pLast->offsMod)
        fprintf(hTrap, "  (both in %s)",
                XqsReadMod(psf->fSym, szBuffer, pLast) ? szBuffer : "[n/a]");
    }
    else
      fprintf(hTrap, "  (in %s and %s)",
              XqsReadMod(psf->fSym, szBuffer, pLast) ? szBuffer : "[n/a]",
              XqsReadMod(psf->fSym, bigBuf, pSym) ? bigBuf : "[n/a]");
  }

  return;
}

/*****************************************************************************/

BOOL    XqsReadName(FILE* fSym, char* pText, XQSYM* pSym)
{
  /* since offsName should never be zero (i.e. pointing to the
   * beginning of the file), assume the target lies between
   * the start of the seg and the first listed symbol.
   */
  if (!pSym->offsName) {
    strcpy(pText, "[start]");
    return TRUE;
  }

  /* read the symbol name */
  if (!pSym->cbName ||
      fseek(fSym, pSym->offsName, SEEK_SET) ||
      fread(pText, 1, pSym->cbName, fSym) != pSym->cbName)
    return FALSE;

  return TRUE;
}

/*****************************************************************************/

BOOL    XqsReadMod(FILE* fSym, char* pText, XQSYM* pSym)
{
  /* if everything looks good, get the module name */
  if (!pSym->offsMod || !pSym->cbMod ||
      fseek(fSym, pSym->offsMod, SEEK_SET) ||
      fread(pText, 1, pSym->cbMod, fSym) != pSym->cbMod)
    return FALSE;

  return TRUE;
}

/*****************************************************************************/
/*****************************************************************************/

SYMFILE* InitSymbolFile(ULONG ulSeg, HMODULE hMod, char* pszFile)
{
  static ULONG  ulLRU = 0;

  BOOL      ok;
  SYMFILE*  psf;
  SYMFILE*  psfSave;
  SYMFILE*  psfLRU;

  if (!hMod)
    return 0;

  ulLRU++;
  psfSave = 0;
  psfLRU = 0;

  /* Search the list of open symfiles for a match.  If one points to the
   * correct file & seg, reuse it.  If the file matches but not the seg,
   * save it to reuse the open file.  Exit at the first unused entry.
   */
  for (psf = asf; psf < &asf[SYMFILE_CNT] && psf->hMod; psf++) {
    if (psf->hMod == hMod) {
      if (psf->seg == ulSeg) {
        psf->lru = ulLRU;
        return psf;
      }
      psfSave = psf;
    }

    if (!psfLRU || psf->lru < psfLRU->lru)
      psfLRU = psf;
  }

  /* If all of the slots are in use, recycle the least recently used entry. */
  if (psf >= &asf[SYMFILE_CNT]) {
    if (psfLRU != psfSave) {
      if (!(psfLRU->sfFlags & SYMFILE_MULTIUSE) && psfLRU->fSym)
        fclose(psfLRU->fSym);
      memset(psfLRU, 0, sizeof(SYMFILE));
    }
    psf = psfLRU;
  }

  psf->hMod = hMod;
  psf->seg  = ulSeg;
  psf->lru = ulLRU;
  psf->pBuffer = symBuffer;

  /* If we're reusing an existing file, copy some data and flag both the
   * original & duplicate entries to prevent the file from being closed.
   * Otherwise, open the new file.
   */
  if (psfSave) {
    psfSave->sfFlags |= SYMFILE_MULTIUSE;
    psf->fSym = psfSave->fSym;
    psf->cbFile = psfSave->cbFile;
    psf->sfFlags = psfSave->sfFlags;
    ok = TRUE;
  }
  else
    ok = OpenSymbolFile(psf, pszFile);

  /* Find the requested seg */
  if (ok) {
    if (psf->sfFlags & SYMFILE_XQS)
      ok = XqsFindSegment(psf);
    else
      ok = SymFindSegment(psf);
  }

  /* If there was an error, close any newly-opened file and clear the entry */
  if (!ok) {
    if (!(psf->sfFlags & SYMFILE_MULTIUSE) && psf->fSym)
      fclose(psf->fSym);
    memset(psf, 0, sizeof(SYMFILE));
    psf = 0;
  }

  return psf;
}

/*****************************************************************************/

BOOL    OpenSymbolFile(SYMFILE* psf, char* pszFile)
{
  char *    pDot;
  char *    pBksl;

  strcpy(psf->pBuffer, pszFile);

  /* Replace the file extension with '.sym', then '.xqs' */
  pDot = strrchr(psf->pBuffer, '.');
  if (!pDot)
    pDot = strchr(psf->pBuffer, 0);

  strcpy(pDot, ".SYM");
  psf->fSym = fopen(psf->pBuffer, "rb");
  if (!psf->fSym) {
    strcpy(pDot, ".XQS");
    psf->fSym = fopen(psf->pBuffer, "rb");
    if (psf->fSym)
      psf->sfFlags |= SYMFILE_XQS;
  }

  /* If it can't be opened using the f/q path, try the current directory. */
  if (!psf->fSym) {
    pBksl = strrchr(psf->pBuffer, '\\');
    if (pBksl) {
      strcpy(pDot, ".SYM");
      psf->fSym = fopen(pBksl + 1, "rb");
      if (!psf->fSym) {
        strcpy(pDot, ".XQS");
        psf->fSym = fopen(pBksl + 1, "rb");
        if (psf->fSym)
          psf->sfFlags |= SYMFILE_XQS;
      }
    }
  }

  if (!psf->fSym)
    return FALSE;

  /* Save the file's size.  xxxFindSegment() will do a SEEK_SET. */
  fseek(psf->fSym, 0, SEEK_END);
  psf->cbFile = (ULONG)ftell(psf->fSym);
  if (psf->cbFile == (ULONG)-1) {
    fprintf(hTrap, " Can not determine .sym file size ");
    return FALSE;
  }

  return TRUE;
}

/*****************************************************************************/

BOOL    SymFindSegment(SYMFILE* psf)
{
  BOOL      ok;
  ULONG     offsNextSeg;
  ULONG     pSymDef;
  ULONG     offs;
  ULONG     adjust;
  MAPDEF *  pmd;
  SEGDEF *  psd;

  fseek(psf->fSym, 0, SEEK_SET);

  /* Read the MAPDEF at the beginning of the file. */
  pmd = (MAPDEF*)psf->pBuffer;
  if (fread(pmd, sizeof(MAPDEF), 1, psf->fSym) != 1) {
    fprintf(hTrap, " Can not read MAPDEF ");
    return FALSE;
  }

  if (psf->seg > pmd->cSegs) {
    fprintf(hTrap, " [n/a] ");
    return FALSE;
  }

  psf->offsThisSeg = pmd->ppSegDef * 16;
  psf->maxSymLth = pmd->cbMaxSym;

  /* Step through each SEGDEF until we find the one we need,
   * or we find it isn't present, or we reach the end of the file.
   */
  ok = FALSE;
  psd = (SEGDEF*)psf->pBuffer;
  while (psf->offsThisSeg && psf->offsThisSeg < psf->cbFile) {

    psf->offsThisSeg = SymGetNextSegment(psf, psf->offsThisSeg, psd);
    if (!psf->offsThisSeg)
      break;

    if (psd->wSegNum == psf->seg) {
      ok = TRUE;
      break;
    }

    if (psd->wSegNum > psf->seg) {
      fprintf(hTrap, " [n/a] ");
      break;
    }

    psf->offsThisSeg = psd->ppNextSeg * 16;
  }

  if (!ok)
    return FALSE;

  /* Save some info we'll need, then find the offset of the next seg. */
  psf->cntSyms  = psd->cSymbols;
  psf->segFlags = psd->bFlags;
  pSymDef = psd->pSymDef;

  if (!psd->ppNextSeg)
    offsNextSeg = psf->cbFile - sizeof(LAST_MAPDEF);
  else
    offsNextSeg = SymGetNextSegment(psf, psd->ppNextSeg * 16, psd);

  if (!offsNextSeg)
    return FALSE;

#define XQ_OVERHEAD (sizeof(SYMDEF32) - 1 + (2 * sizeof(USHORT)))

  /* See if there's any chance that cntSym has rolled over because there are
   * over 64k symbols.  If so, the average length of a symbol name will be
   * absurdly high.  Test the length against the lesser of MAPDEF->cbMaxSym
   * and 80.  Note: 80 may be too high but heavily mangled C++ symbols that
   * use multiple namespaces could drive it close to that length. RLW
  */
  if (offsNextSeg - psf->offsThisSeg > 0x10000 * (XQ_OVERHEAD + 3)) {
    adjust = (psf->maxSymLth > 80 ? 80 : psf->maxSymLth) + XQ_OVERHEAD;
    while (((offsNextSeg - psf->offsThisSeg) / psf->cntSyms) > adjust)
      psf->cntSyms += 0x10000;
  }

  /* The end of the symbol pointer table should be roughly equal to the
   * offset of the next SEGDEG, but it will be off by some multiple of
   * 64k if this seg has more than 64k of symbols.  This calculates the
   * adjustment needed to correctly locate the start of the table,  RLW
   */
  offs = psf->offsThisSeg + pSymDef + (2 * psf->cntSyms * sizeof(USHORT));
  adjust = (offsNextSeg - offs) & 0xFFFF0000;
  psf->offsSymPtr = psf->offsThisSeg + pSymDef + adjust;

  return TRUE;
}

/*****************************************************************************/

ULONG   SymGetNextSegment(SYMFILE* psf, ULONG offsSeg, SEGDEF* psd)
{
  /* Look for the next SegDef starting at the offset given, then validate it.
   * If validation fails, it may be because the current seg has more than 1mb
   * of symbol data (the maximum this file format was designed to handle). If
   * so, keep seeking 1mb ahead until validation succeeds or we reach EOF. RLW
   */
  while (offsSeg < psf->cbFile) {

    if (fseek(psf->fSym, offsSeg, SEEK_SET)) {
      fprintf(hTrap, " Can not seek to SegDef at %x ", offsSeg);
      return 0;
    }

    if (fread(psd, sizeof(SEGDEF), 1, psf->fSym) != 1) {
      fprintf(hTrap, " Can not read SegDef at %x ", offsSeg);
      return 0;
    }

    if (!psd->wInstance0 && !psd->wInstance1 && !psd->wInstance2 &&
        !psd->bReserved1 && psd->cSymbols && psd->pSymDef &&
        psd->wSegNum && psd->cbSegName && psd->achSegName[0]) {
      return offsSeg;
    }

    offsSeg += 0x100000;
  }

  fprintf(hTrap, " [n/a] ");

  return 0;
}

/*****************************************************************************/

BOOL    XqsFindSegment(SYMFILE* psf)
{
  BOOL      ok;
  XQFILE *  pxf;
  XQSEG *   pxs;

  fseek(psf->fSym, 0, SEEK_SET);

  /* Read the XQFILE at the beginning of the file. */
  pxf = (XQFILE*)psf->pBuffer;
  if (fread(pxf, sizeof(XQFILE), 1, psf->fSym) != 1) {
    fprintf(hTrap, " Can not read XQFILE ");
    return FALSE;
  }

  /* If the file's signature is missing or this isn't v1.x of
   * the file format or any of the file is compressed, exit.  
   * (Compression isn't supported yet, so this test is for future-proofing.)
   */
  if (pxf->magic != XQFILE_MAGIC ||
      (pxf->version & 0xff) != 1 ||
      (pxf->flags & XQFLAG_ZIP))
    return FALSE;

  psf->offsThisSeg = pxf->firstSeg;

  /* Step through each SEGDEF until we find the one we need,
   * or we find it isn't present, or we reach the end of the file.
   */
  ok = FALSE;
  pxs = (XQSEG*)psf->pBuffer;
  while (psf->offsThisSeg && psf->offsThisSeg < psf->cbFile) {

    if (fseek(psf->fSym, psf->offsThisSeg, SEEK_SET)) {
      fprintf(hTrap, " Can not seek to XQSEG at %x ", psf->offsThisSeg);
      return FALSE;
    }

    if (fread(pxs, sizeof(XQSEG), 1, psf->fSym) != 1) {
      fprintf(hTrap, " Can not read XQSEG at %x ", psf->offsThisSeg);
      return FALSE;
    }

    if (pxs->magic != XQSEG_MAGIC) {
      fprintf(hTrap, " Invalid XQSEG at %x ", psf->offsThisSeg);
      return FALSE;
    }

    if (pxs->seg > psf->seg) {
      fprintf(hTrap, " [n/a] ");
      return FALSE;
    }

    if (pxs->seg == psf->seg) {
      psf->cntSyms  = pxs->cntSym;
      psf->offsSymPtr = pxs->offsSym;
      psf->cbXQSYM = pxs->cbXQSYM;
      return TRUE;
    }

    psf->offsThisSeg = pxs->offsNext;
  }

  fprintf(hTrap, " [n/a] ");

  return FALSE;
}

/*****************************************************************************/
/*****************************************************************************/

void    CloseSymbolFiles(void)
{
  SYMFILE*  psf;
  SYMFILE*  psf2;

  for (psf = asf; psf < &asf[SYMFILE_CNT]; psf++) {
    if (!psf->fSym)
      continue;

    fclose(psf->fSym);

    /* ensure a file with multiple entries only gets closed once */
    for (psf2 = psf + 1; psf2 < &asf[SYMFILE_CNT]; psf2++) {
      if (psf2->fSym == psf->fSym)
        psf2->fSym = 0;
    }
  }

  /* clear the array in case the handler gets invoked again */
  memset(asf, 0, sizeof(asf));

  return;
}

/*****************************************************************************/

