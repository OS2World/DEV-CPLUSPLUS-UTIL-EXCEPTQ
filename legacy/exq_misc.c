/*****************************************************************************/
/*
 *  exq_misc.c - stuff left on the cutting room floor
 *
 *  Parts of this file are
 *    Copyright (c) 2000-2010 Steven Levine and Associates, Inc.
 *
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
#ifdef WANT_BCOA
/*****************************************************************************/
/*
 * Debug info definitions apply to Borland Open Architecture debug format
 * Requires hlldbg.h for common definitions
 *
 * 27 May 08 SHL Baseline
*/

/* Known formats
 *
 * FB09  Borland Open Architecture BC2.0 OS/2
*/

/* "FB" Borland OA signature */
#define BCOADBG_SIG         0x4246

#define SSTMODULE_BCOA      0x120
#define SSTTYPES_BCOA       0x121
#define SSTSYMBOLS_BCOA     0x124
#define SSTALIGNSYM_BCOA    0x125
#define SSTSRCMODULE_BCOA   0x127
#define SSTGLOBALSYM_BCOA   0x129
#define SSTGLOBALTYPES_BCOA 0x12b
#define SSTNAMES_BCOA       0x130

/*****************************************************************************/

#define MAX_AUTONAMBYTES  64
#define MAX_USERDEFS      150
#define MAX_POINTERS      150
#define MAX_AUTOVARS      50

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

#pragma pack(1)

static USHORT       userdef_count;
static USHORT       pointer_count;
static ULONG        autovar_count = 0;
static ULONG        ulNearestPubOffset; // Used for local var matching
static ULONG        ulSymOffset;        // Offset of function to match for local variables display
static char         szSymFuncName[256]; // Function name at this offset

static XQ_USERDEF   userdefs[MAX_USERDEFS];
static XQ_POINTERS  pointers[MAX_POINTERS];
static XQ_AUTOVARS  autovars[MAX_AUTOVARS];

/*****************************************************************************/

#define DBG_BCOA 1   // Enable to generate BCOA debug output

int     ReadBCOADebug(INT fh, USHORT usSegNum, ULONG ulOffset, CHAR *pszFileName)
{
  UINT CurrSymSeg = 0;
  UINT ulNearestPub = 0;
  UINT NearestFile = 0;
  UINT NearestLine = 0;
  UINT ssdir_count;
  UINT namelen;
  UINT numlines;
  UINT uModIndex = 0;
  INT nBytesRead;
  UINT uDirNdx;
  UINT uNdx;
  ssLineEntry32 LineEntry;
  ssFileNum32 FileInfo;
  ssFirstLineEntry32 FirstLine;
  BOOL dump_vars = FALSE;
  USHORT idx;
  BOOL read_types = FALSE;
  ULONG ul;
  ULONG ulFileOffset;
  ssDir32 *pDirTab32;

  debug_tail_rec  debug_tail;
  debug_head_rec  debug_head;
  ssModule32  ssmod32;
  ssPublic32  sspub32;
  char * psz;
  ULONG  lfaBase;

  /* See if any debug data info */
  if (lseek(fh, -8L, SEEK_END) == -1) {
    fprintf(hTrap, "Can not seek SEEK_END - 8 %s (%d)\n", pszFileName, errno);
    return 18;
  }

  if (read(fh, &debug_tail, 8) == -1) {
    fprintf(hTrap, "Can not read debug sig from %s (%d)\n", pszFileName, errno);
    return 19;
  }
  if (debug_tail.signature != BCOADBG_SIG) {
    /* fputs("\nNo BCOA debug data stored.\n",hTrap); */
    return 100;
  }

  if ((lfaBase = lseek(fh, -debug_tail.offset, SEEK_END)) == -1L) {
    fprintf(hTrap, "Can not seek to debug data tail in %s (%d)\n", pszFileName, errno);
    return 20;
  }

  if (read(fh, &debug_head, 8) == -1) {
    fprintf(hTrap, "Error %u reading BCOA debug data header in %s\n", errno, pszFileName);
    return 21;
  }

  // 27 May 08 SHL fixme to read entire hll_dirinfo header
  if (lseek(fh, debug_head.lfoDir - 8 + 4, SEEK_CUR) == -1) {
    fprintf(hTrap, "Error %u seeking to BCOA debug data directory in %s\n", errno, pszFileName);
    return 22;
  }

  if (read(fh, &ssdir_count, 4) == -1) {
    fprintf(hTrap, "Error %u reading BCOA debug data directory count in %s\n", errno, pszFileName);
    return 23;
  }

  /* Allocate buffer to hold subsection directory table */
  if ((pDirTab32 = (ssDir32 *)calloc(ssdir_count, sizeof(ssDir32))) == NULL) {
    fputs("Out of memory!", hTrap);
    return -1;
  }

  /* Read subsection directory into buffer */
  if (read(fh, pDirTab32, ssdir_count * sizeof(ssDir32)) == -1) {
    fprintf(hTrap, "Error %u reading BCOA debug data directory from %s\n", errno, pszFileName);
    free(pDirTab32);
    return 24;
  }

  for (uDirNdx = 0; uDirNdx < ssdir_count;) {
    /* Scan directory for 1st module record */
    if (pDirTab32[uDirNdx].sst != SSTMODULES) {
      uDirNdx++;
      continue;
    }
    /* point to subsection */
    lseek(fh, pDirTab32[uDirNdx].lfoStart + lfaBase, SEEK_SET);
    read(fh, &ssmod32.csBase, sizeof(ssmod32));  // Read module header

    read(fh, szModName, (unsigned) ssmod32.csize);  // Read name

    uModIndex = pDirTab32[uDirNdx].modindex;
    szModName[ssmod32.csize] = 0;
    uDirNdx++;

    for (; pDirTab32[uDirNdx].modindex == uModIndex && uDirNdx < ssdir_count; uDirNdx++) {
      /* Position to subsection */
      if (lseek(fh, pDirTab32[uDirNdx].lfoStart + lfaBase, SEEK_SET) == -1) {
        fprintf(hTrap, "Error %u seeking data in %s\n", errno, pszFileName);
        free(pDirTab32);
        return 25;
      }

      switch (pDirTab32[uDirNdx].sst) {

        case SSTPUBLICS:
          nBytesRead = 0;
          while (nBytesRead < pDirTab32[uDirNdx].cb) {
            // 24 May 08 SHL fixme to check read errors
            nBytesRead += read(fh, &sspub32.offset, sizeof(sspub32));
            nBytesRead += read(fh, szFuncName, (unsigned) sspub32.csize);
            szFuncName[sspub32.csize] = 0;
            if (sspub32.segment == usSegNum &&
                sspub32.offset >= ulNearestPub &&
                sspub32.offset <= ulOffset) {
              // Found closer function
              ulNearestPub = sspub32.offset;
              // Remember for local var matching
              ulNearestPubOffset = ulNearestPub;
              read_types = TRUE;
              sprintf(szNearestPubDesc, "%s%s %04X:%08X (%s)",
                      sspub32.type == 1 ? "Abs " : "", szFuncName,
                      sspub32.segment, sspub32.offset, szModName);
            }
          }
          break;

        case SSTSYMBOLS:
          /* Read symbols, so we can dump the auto variables on the stack */
          if (usSegNum != ssmod32.csBase)
            break;

          nBytesRead = 0;
          while (nBytesRead < pDirTab32[uDirNdx].cb) {
            USHORT usLength;
            BYTE b1;
            BYTE b2;
            BYTE bType;
            static symseg_rec symseg;
            static symauto_rec symauto;
            static symproc_rec symproc;

            /* Read encoded length of this subentry */
            nBytesRead += read(fh, &b1, 1);
            if (b1 & 0x80) {
              nBytesRead += read(fh, &b2, 1);
              usLength = ((b1 & 0x7F) << 8) + b2;
            }
            else
              usLength = b1;

            ulFileOffset = tell(fh);
            nBytesRead += read(fh, &bType, 1);

            switch (bType) {
              case SYM_CHANGESEG:
                read(fh, &symseg, sizeof(symseg));
                CurrSymSeg = symseg.seg_no;
                break;

              case SYM_PROC:
              case SYM_CPPPROC:
                read(fh, &symproc, sizeof(symproc));
                read(fh, szVarName, symproc.name_len);
                szVarName[symproc.name_len] = 0;

                if (CurrSymSeg == usSegNum &&
                    ulOffset >= symproc.offset &&
                    ulOffset < symproc.offset + symproc.length) {
                  // Got function name, try to find locals
                  dump_vars = TRUE;
                  autovar_count = 0;
                  ulSymOffset = symproc.offset;
                  strcpy(szSymFuncName, szVarName);
                }
                else
                  dump_vars = FALSE;
                break;

              case SYM_AUTO:
                if (!dump_vars)
                  break;

                read(fh, &symauto, sizeof(symauto));
                read(fh, szVarName, symauto.name_len);
                szVarName[symauto.name_len] = 0;

                if (autovar_count < MAX_AUTOVARS) {
                  strncpy(autovars[autovar_count].name, szVarName, MAX_AUTONAMBYTES);
                  autovars[autovar_count].name[MAX_AUTONAMBYTES - 1] = 0;
                  autovars[autovar_count].stack_offset = symauto.stack_offset;
                  autovars[autovar_count].type_idx = symauto.type_idx;
                  autovar_count++;
                }
                break;

            } // switch bType

            nBytesRead += usLength;
            lseek(fh, ulFileOffset + usLength, SEEK_SET);  // Position to next symbol record
          } // while
          break;      // SSTSYMBOLS

        case SSTTYPES:
          if (!read_types)
            break;

          nBytesRead = 0;
          idx = 0x200;
          userdef_count = 0;
          pointer_count = 0;
          while (nBytesRead < pDirTab32[uDirNdx].cb) {
            static type_rec type;
            static type_userdefrec udef;
            static type_pointerrec point;

            /* Remember current file offset */
            ulFileOffset = tell(fh);

            /* Read the length of this subentry */
            read(fh, &type, sizeof(type));
            nBytesRead += sizeof(type);

            switch (type.type) {
              case TYPE_USERDEF:
                if (userdef_count >= MAX_USERDEFS)
                  break;

                read(fh, &udef, sizeof(udef));
                read(fh, szVarName, udef.name_len);
                szVarName[udef.name_len] = 0;

                // Insert userdef in table
                userdefs[userdef_count].idx = idx;
                userdefs[userdef_count].type_index = udef.type_index;
                memcpy(userdefs[userdef_count].name, szVarName, min(udef.name_len + 1, 32));
                userdefs[userdef_count].name[32] = 0;
                userdef_count++;
                break;

              case TYPE_POINTER:
                if (pointer_count >= MAX_POINTERS)
                  break;

                read(fh, &point, sizeof(point));
                read(fh, szVarName, point.name_len);
                szVarName[point.name_len] = 0;

                // Insert pointer def in table
                pointers[pointer_count].idx = idx;
                pointers[pointer_count].type_index = point.type_index;
                memcpy(pointers[pointer_count].name, szVarName, min(point.name_len + 1, 32));
                pointers[pointer_count].name[32] = 0;
                pointers[pointer_count].type_qual = type.type_qual;
                pointer_count++;
                break;
            } // switch type.type

            ++idx;
            nBytesRead += type.length;
            lseek(fh, ulFileOffset + type.length + 2, SEEK_SET);
          } // while
          break;      // SSTTYPES

        case SSTSRCLINES32:
          if (usSegNum != ssmod32.csBase)
            break;

          /* find first type 0 line number record
           * skip leading type 3 pszFileName list records
           */
          ulFileOffset = 0;
          do {
            read(fh, &FirstLine, sizeof(FirstLine));

            if (FirstLine.LineNum != 0) {
              fputs("Missing Line table information\n", hTrap);
              FirstLine.numlines = 0;
              break;
            }
            /* If type 0..3, read rest of header
             * Type 4 omits length/seg_address field
             */
            if (FirstLine.entry_type < 4) {
              read(fh, &ul, 4);
              // If type 3, remember start of file names table and position after
              if (FirstLine.entry_type == 3) {
                if (!ulFileOffset)
                  ulFileOffset = tell(fh);
                  lseek(fh, ul, SEEK_CUR);
                }
              }
          } while (FirstLine.entry_type == 3);

          numlines = FirstLine.numlines;

          for (uNdx = 0; uNdx < numlines; uNdx++) {
            switch (FirstLine.entry_type) {
              case LINEREC_SRC_LINES:
                read(fh, &LineEntry, sizeof(LineEntry));
                /* Changed by Kim Rasmussen 26/06 1996 to ignore linenumber 0 */
                /* if (LineEntry.ulOffset+ssmod32.csOff<=ulOffset && LineEntry.ulOffset+ssmod32.csOff>=NearestLine) {} */
                if (LineEntry.LineNum &&
                    LineEntry.ulOffset + ssmod32.csOff >= NearestLine &&
                    LineEntry.ulOffset + ssmod32.csOff <= ulOffset) {
                  // Found better match
                  NearestLine = LineEntry.ulOffset;
                  NearestFile = LineEntry.FileNum;
                  sprintf(szNearestLine, "#%hu", LineEntry.LineNum);
                }
                break;
        
              case LINEREC_LIST_LINES:
                lseek(fh, sizeof(linlist_rec), SEEK_CUR);
                break;
        
              case LINEREC_SRCLIST_LINES:
                lseek(fh, sizeof(linsourcelist_rec), SEEK_CUR);
                break;
        
              case LINEREC_FILENAMES:
                lseek(fh, sizeof(filenam_rec), SEEK_CUR);
                break;
        
              case LINEREC_PATHINFO:
                lseek(fh, sizeof(pathtab_rec), SEEK_CUR);
                break;
            } /* switch FirstLine.entry_type */
          } /* for */

          if (NearestFile != 0) {
            // Have filename index - find name
            // lseek back to filenames entry
            lseek(fh, ulFileOffset, SEEK_SET);
            read(fh, &FileInfo, sizeof(FileInfo));
            namelen = 0;
            for (uNdx = 1; uNdx <= FileInfo.file_count; uNdx++) {
              namelen = 0;  // in case read error
              read(fh, &namelen, 1);
              read(fh, szFuncName, namelen);
              if (uNdx == NearestFile)
              break;  // Got it
            }
            szFuncName[namelen] = 0;
            psz = strrchr(szFuncName, '\\');
            if (psz == NULL)
              psz = szFuncName;
            else
              psz++;
            strcpy(szNearestFile, psz);  // Record file name
          }
          else {
            *szNearestFile = 0;
          }
          break; // SSTSRCLINES32

#ifdef DBG_BCOA
        default:
          fprintf(hTrap, "BCOA type %u unknown%s\n", pDirTab32[uDirNdx].sst);
#endif

      } /* switch sst */
    } /* for same module */
  } /* for uDirNdx < ssdir_count */

  free(pDirTab32);
  return 0;
}

/*****************************************************************************/
#endif // WANT_BCOA
/*****************************************************************************/

/*****************************************************************************/
#ifdef WANT_DOSDEBUG
/*****************************************************************************/

APIRET16 APIENTRY16 DOS16SIZESEG(USHORT Seg, ULONG *_Seg16 Size);
APIRET16 APIENTRY16 DOS16ALLOCSEG(USHORT cbSize,        /* number of bytes requested */
                                  USHORT * _Seg16 pSel, /* sector allocated (returned) */
                                  USHORT fsAlloc);      /* attributes requested */

void    ListModules(void);
void    GetObjects(uDB_t* pDbgBuf, HMODULE hMte, PSZ pszName, ULONG Pid);

/*****************************************************************************/

/* List loaded modules using DosDebug
 *
 * Note:  the program "debuggee.exe" must be available
 *        somewhere on the PATH for this function to work.
 * TBD:   look for it in the directory containing exceptq.dll
*/

void    ListModules(void)
{
  static uDB_t  DbgBuf;

  APIRET      rc;
  APIRET16    rc16;
  QSLREC *    pLib;
  QSPTRREC *  pRec;
  RESULTCODES ReturnCodes = {0,0};
  USHORT      Selector;
  UCHAR       szLoadError[16];
  UCHAR *     szProcessName = "DEBUGGEE.EXE";
  ULONG *     pBuf;

  rc16 = DOS16ALLOCSEG(0xFFFF, &Selector, 0);
  if (rc16) {
    fprintf(hTrap, "DosAllocSeg Failed %hd\n", rc16);
    return;
  }

  pBuf = MAKEP(Selector, 0);
  rc16 = DOSQPROCSTATUS(pBuf, 0xFFFF);
  if (rc16) {
    fprintf(hTrap, "DosQProcStatus Failed %hd\n", rc16);
    return;
  }

  *szLoadError = 0;
  rc = DosExecPgm(szLoadError,          /* Object name buffer */
                  sizeof(szLoadError),  /* Length of object name buffer */
                  EXEC_TRACE,           /* Asynchronous/Trace flags */
                  "Debug",              /* Argument string */
                  NULL,                 /* Environment string */
                  &ReturnCodes,         /* Termination codes */
                  szProcessName);       /* Program file name */
  if (rc) {
    fprintf(hTrap, "rc %d; Process id %x; Return code %x  Failing module= '%s'\n",
            rc, ReturnCodes.codeTerminate, ReturnCodes.codeResult,
            szLoadError);
    return;
  }

  fprintf(hTrap, "Connecting  to PID %d\n", ReturnCodes.codeTerminate);
  DbgBuf.Cmd = DBG_C_Connect;    /* Indicate that a Connect is requested */
  DbgBuf.Pid = ReturnCodes.codeTerminate;
  DbgBuf.Tid = 0;
  DbgBuf.Value = DBG_L_386;

  rc = DosDebug(&DbgBuf);
  if (rc) {
    fprintf(hTrap, "DosDebug error return code = %ld Note %8.8lX\n", rc, DbgBuf.Cmd);
    fprintf(hTrap, "Value = %8.8lX %ld\n", DbgBuf.Value, DbgBuf.Value);
/* should there be a return here? */
  }

  fprintf(hTrap, "Connected to PID %d\n", ReturnCodes.codeTerminate);
  pRec = (QSPTRREC*)pBuf;
  pLib = pRec->pLibRec;

  while (pLib) {
    GetObjects(&DbgBuf, pLib->hmte, pLib->pName, ReturnCodes.codeTerminate);
    pLib = pLib->pNextRec;
  }

  return;
}

/*****************************************************************************/
/* Lists object for module using DosDebug */

void    GetObjects(uDB_t* pDbgBuf, HMODULE hMte, PSZ pszName, ULONG Pid)
{
  APIRET    rc;
  APIRET16  rc16;
  ULONG     ulSize;
  UINT      uObjNum;

  pDbgBuf->MTE = (ULONG)hMte;
  rc = 0;
  fprintf(hTrap, "DLL %s Handle %d\n", pszName, hMte);
  fputs("Object Number    Address    Length     Flags      Type\n", hTrap);

  for (uObjNum = 1; uObjNum < 256; uObjNum++) {
    pDbgBuf->Cmd = DBG_C_NumToAddr;
    pDbgBuf->Pid = Pid;
    pDbgBuf->Value = uObjNum;    /* Get nth object address in module with given MTE */
    pDbgBuf->Buffer = 0;
    pDbgBuf->Len = 0;

    rc = DosDebug(pDbgBuf);
    if (rc || pDbgBuf->Cmd) {
      // printf("DosDebug return code = %ld Notification %8.8lX\n", rc,pDbgBuf->Cmd);
      // printf("Value                = %8.8lX %ld\n",pDbgBuf->Value,pDbgBuf->Value);
      break;
    }

    pDbgBuf->Len = 0;
    pDbgBuf->Value = 0;
    if (pDbgBuf->Addr != 0) {
      pDbgBuf->Cmd = DBG_C_AddrToObject;
      pDbgBuf->Pid = Pid;

      rc = DosDebug(pDbgBuf);
      if (rc || pDbgBuf->Cmd) {
        pDbgBuf->Len = 0;
        pDbgBuf->Value = 0;
      }
    }

    fprintf(hTrap, "      % 6.6d    %8.8lX   %8.8lX   %8.8lX ",
            uObjNum, pDbgBuf->Addr, pDbgBuf->Len, pDbgBuf->Value);

    // fixme to know if DOS16SIZESEG really useful here
    if (!pDbgBuf->Addr)
      fputs(" - ?\n", hTrap);
    else {
      rc16 = DOS16SIZESEG(SELECTOROF(pDbgBuf->Addr), &ulSize);
      if (!rc16 && (~pDbgBuf->Value & OBJBIGDEF))
        fprintf(hTrap, " - 16:16  Selector %4.4hX\n",
                SELECTOROF((PVOID)pDbgBuf->Addr));
      else
        fputs(" - 32 Bits\n", hTrap);
    }
  } /* for objects */

  fputc('\n', hTrap);
  return;
}

/*****************************************************************************/
#endif /* WANT_DOSDEBUG */
/*****************************************************************************/

