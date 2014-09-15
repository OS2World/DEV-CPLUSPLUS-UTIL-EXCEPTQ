/*****************************************************************************/
/*
 *  exq_cv.c - CodeView (16-bit) debug data parser
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

int     SetupCodeView(INT fh, USHORT usSegNum, USHORT usOffset, CHAR *pszFileName)
{
  static int rc;

#if 0
  /* RW - What is this supposed to do?  It appears to be totally unreferenced! */

  static struct new_seg *pNewSeg;

  // Allocate segment table buffer
  pNewSeg = (struct new_seg *)calloc(NE_CSEG(new_hdr), sizeof(struct new_seg));
  if (!pNewSeg) {
    fputs("Out of memory!", hTrap);
    close(fh);
    return -1;
  }

  if (lseek(fh, E_LFANEW(old_hdr) + NE_SEGTAB(new_hdr), SEEK_SET) == -1L) {
    fprintf(hTrap, "Can not seek to segment table in %s (%d)\n", pszFileName, errno);
    free(pNewSeg);
    close(fh);
    return 9;
  }

  if (read(fh, pNewSeg, NE_CSEG(new_hdr) * sizeof(struct new_seg)) == -1) {
    fprintf(hTrap, "Can not read segment table from %s (%d)\n", pszFileName, errno);
    free(pNewSeg);
    close(fh);
    return 10;
  }
#endif

  rc = Read16CodeView(fh, usSegNum + 1, usOffset, pszFileName);
  close(fh);

  /* If debug data not in executable, try DBG file */
  if (rc) {
    strcpy(pszFileName + strlen(pszFileName) - 3, "DBG");
    fh = sopen(pszFileName, O_RDONLY | O_BINARY, SH_DENYNO);
    if (fh != -1) {
      rc = Read16CodeView(fh, usSegNum + 1, usOffset, pszFileName);
      close(fh);
    }
  }

  if (!rc)
    fprintf(hTrap, " %s%s %s\n", szNearestFile, szNearestLine, szNearestPubDesc);

#if 0
  free(pNewSeg);
#endif

  return rc;
}

/*****************************************************************************/

/* Read 16 bit CodeView data for cs:ip, return data in globals */

int     Read16CodeView(INT fh, USHORT usSegNum, USHORT usOffset, CHAR *pszFileName)
{
  /* Make static to limit stack usage - could be auto */
  static USHORT   offset;
  static USHORT   usNearestPublic;
  static USHORT   usNearestLine;
  static USHORT   numdir;
  static USHORT   namelen;
  static USHORT   numlines;
  static USHORT   line;
  static USHORT   ModIndex;
  static INT      nBytesRead;
  static UINT     uDirNdx;
  static UINT     uLineNdx;
  static LONG     lfaBase;
  static ssDir16 *pDirTab;
  static ssModule ssmod;
  static ssPublic sspub;
  static debug_tail_rec debug_tail;
  static debug_head_rec debug_head;

  ModIndex = 0;
  /* Check if CODEVIEW data exists */
  if (lseek(fh, -8L, SEEK_END) == -1) {
    fprintf(hTrap, "Error %u seeking CodeView table in %s\n", errno, pszFileName);
    return 18;
  }
  if (read(fh, &debug_tail, 8) == -1) {
    fprintf(hTrap, "Error %u reading debug info from %s\n", errno, pszFileName);
    return 19;
  }
  if (debug_tail.signature != HLLDBG_SIG) {
    /* fputs("\nNo CodeView information stored.\n",hTrap); */
    return 100;
  }
  if ((lfaBase = lseek(fh, -debug_tail.offset, SEEK_END)) == -1L) {
    fprintf(hTrap, "Error %u seeking codeview data header in %s\n", errno, pszFileName);
    return 20;
  }
  if (read(fh, &debug_head, 8) == -1) {
    fprintf(hTrap, "Error %u reading codeview data header in %s\n", errno, pszFileName);
    return 21;
  }
  if (lseek(fh, debug_head.lfoDir - 8, SEEK_CUR) == -1) {
    fprintf(hTrap, "Error %u seeking dir codeview data in %s\n", errno, pszFileName);
    return 22;
  }
  if (read(fh, &numdir, 2) == -1) {
    fprintf(hTrap, "Error %u reading dir codeview data in %s\n", errno, pszFileName);
    return 23;
  }
  /* Allocate dir table buffer */
  if ((pDirTab = (ssDir16 *)calloc(numdir, sizeof(ssDir16))) == NULL) {
    fputs("Out of memory!", hTrap);
    return -1;
  }

  /* Read dir table into buffer */
  if (read(fh, pDirTab, numdir * sizeof(ssDir16)) == -1) {
    fprintf(hTrap, "Error %u reading codeview DirTab from %s\n", errno, pszFileName);
    free(pDirTab);
    return 24;
  }

  uDirNdx = 0;
  while (uDirNdx < numdir) {
    if (pDirTab[uDirNdx].sst != SSTMODULES) {
      uDirNdx++;
      continue;
    }
    usNearestPublic = 0;
    usNearestLine = 0;
    /* point to subsection */
    if (lseek(fh, pDirTab[uDirNdx].lfoStart + lfaBase, SEEK_SET) == -1) {
      fprintf(hTrap, "Error %u seeking to csBase in %s\n", errno, pszFileName);
      return 25;
    }
    if (read(fh, &ssmod.csBase, sizeof(ssmod)) == -1) {
      fprintf(hTrap, "Error %u reading csBase from %s\n", errno, pszFileName);
      return 26;
    }
    if (read(fh, szModName, (UINT)ssmod.csize) == -1) {
      fprintf(hTrap, "Error %u reading module name from %s\n", errno, pszFileName);
      return 27;
    }
    ModIndex = pDirTab[uDirNdx].modindex;
    szModName[ssmod.csize] = 0;
    uDirNdx++;
    while (pDirTab[uDirNdx].modindex == ModIndex && uDirNdx < numdir) {
      /* point to subsection */
      if (lseek(fh, pDirTab[uDirNdx].lfoStart + lfaBase, SEEK_SET) == -1) {
        fprintf(hTrap, "Error %u seeking to SST_ section in %s\n", errno, pszFileName);
        return 28;
      }
      switch (pDirTab[uDirNdx].sst) {

        case SSTPUBLICS:
          nBytesRead = 0;
          while (nBytesRead < pDirTab[uDirNdx].cb) {
            /* 10 Oct 07 SHL fixme to check read errors */
            nBytesRead += read(fh, &sspub.offset, sizeof(sspub));
            nBytesRead += read(fh, szFuncName, (unsigned)sspub.csize);
            szFuncName[sspub.csize] = 0;
            if (sspub.segment == usSegNum &&
                sspub.offset >= usNearestPublic &&
                sspub.offset <= usOffset) {
              /* Found better match */
              usNearestPublic = sspub.offset;
              sprintf(szNearestPubDesc, "%s%s %04hX:%04hX (%s)",
                      sspub.type == 1 ? "Abs " : "", szFuncName,
                      sspub.segment, sspub.offset, szModName);
            }
          }
          break;

        case SSTSRCLINES2:
        case SSTSRCLINES:
          if (usSegNum != ssmod.csBase)
            break;
          namelen = 0;
          read(fh, &namelen, 1);
          read(fh, szFuncName, namelen);
          szFuncName[namelen] = 0;
          /* skip 2 zero bytes */
          if (pDirTab[uDirNdx].sst == SSTSRCLINES2)
              read(fh, &numlines, 2);
          read(fh, &numlines, 2);
          for (uLineNdx = 0; uLineNdx < numlines; uLineNdx++) {
            read(fh, &line, 2);
            read(fh, &offset, 2);
            if (offset <= usOffset && offset >= usNearestLine) {
              /* Got better match */
              usNearestLine = offset;
              sprintf(szNearestLine, "#%hu", line);
              strcpy(szNearestFile, szFuncName);
            }
          }
          break;
      } /* switch */
      uDirNdx++;
    } /* while modindex */
  } /* while uDirNdx < numdir */

  free(pDirTab);
  return 0;
}

/*****************************************************************************/

