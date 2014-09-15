/*****************************************************************************/
/*
 *  exq.h - exceptq private header - v7.1
 *
 *  Parts of this file are
 *    Copyright (c) 2000-2010 Steven Levine and Associates, Inc.
 *    Copyright (c) 2010-2011 Richard L Walsh
 *
*/
/*****************************************************************************/

#ifndef EXQ_H_INCLUDED
  #define EXQ_H_INCLUDED

#include "exceptq.h"

#define EXCEPTQ_VERSION "7.10"

/*****************************************************************************/

/* verbosity levels - default is XQ_CONCISE */

#define XQ_TERRIBLYTERSE  1     /* option "TT" */
#define XQ_TERSE          2     /* option "T"  */
#define XQ_CONCISE        3     /* option "C"  */
#define XQ_VERBOSE        4     /* option "V"  */
#define XQ_VERYVERBOSE    5     /* option "VV" */

/*****************************************************************************/

extern BOOL     fReport;
extern BOOL     fBeep;
extern BOOL     fReportInfo;
extern BOOL     fDebug;
extern ULONG    verbosity;
extern FILE *   hTrap;
extern char     szReportInfo[80];
extern char     szBuffer[1024];
extern char     bigBuf[2048];
extern char     szModName[CCHMAXPATH];
extern char     szNearestFile[CCHMAXPATH];  /* %s, for current cs:eip   */
extern char     szNearestLine[16];          /* #%hu, for current cs:eip */
extern char     szNearestPubDesc[512];      /* %s, for current cs:eip   */
extern char     szFuncName[256];            /* Last function name read from debug data */
extern char     szVarName[256];             /* Last variable name read from debug data */

extern struct exe_hdr  old_hdr;
extern struct new_exe  new_hdr;

/*****************************************************************************/

/** exceptq.c **/
void    InitOptions(const char* pszOptions, BOOL* pfInitReportInfo);

/** exq_cv.c **/
int     SetupCodeView(INT fh, USHORT usSegNum, USHORT usOffset, CHAR *pszFileName);
int     Read16CodeView(INT fh, USHORT usSegNum, USHORT usOffset, CHAR *pszFileName);

/** exq_dbg.c **/
APIRET  PrintLineNum(char *pszFileName, ULONG ulObjNum,
                     ULONG ulOffset, BOOL fSaveSymbols);
BOOL    PrintLocalVariables(ULONG ulStackOffset);

/** exq_rpt.c **/
void    ReportException(EXCEPTIONREPORTRECORD* pERepRec,
                        EXCEPTIONREGISTRATIONRECORD* pERegRec,
                        CONTEXTRECORD* pCtxRec,
                        BOOL isDebug);
void    TimedBeep(void);

/** exq_sym.c **/
void    PrintSymbolFromFile(char * pszFile, HMODULE hMod,
                            ULONG ulObjNum, ULONG ulOffset);
void    CloseSymbolFiles(void);

/*****************************************************************************/

#endif /* EXQ_H_INCLUDED */

