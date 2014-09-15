/*****************************************************************************/
/*
 *  exq_rpt.c - exceptq report generator
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
#include <time.h>
#include <ctype.h>

#define INCL_DOS
#define INCL_DOSERRORS
#include <os2.h>

#include "exq.h"
#include "distorm.h"

/*****************************************************************************/
/** 32-bit stuff **/

#define FLATCS ((USHORT)0x5B)
#define FLATDS ((USHORT)0x53)

/* flags used by PrintMemory() */
#define XQM_FMT8      0x08
#define XQM_FMT16     0x10
#define XQM_FMT32     0x20
#define XQM_DWORDS    0x100
#define XQM_WORDS     0x200
#define XQM_BYTES     0x400
#define XQM_CHARS     0x800
#define XQM_FMTMASK   (XQM_FMT8 | XQM_FMT16 | XQM_FMT32)

/* struct used by disassemble routines to reduce stack usage */
typedef struct {
  USHORT    seg16;
  USHORT    addr16;
  ULONG     addr32;
  ULONG     bytesBefore;
  ULONG     bytesAfter;
  ULONG     codeBefore;
  ULONG     codeAfter;
} XQ_DECODE;

/* distorm interface */
typedef _DecodeResult (_System DISTORM_DECODE32)(
                      _OffsetType, const unsigned char*, int, _DecodeType,
                      _DecodedInst*, unsigned int, unsigned int*);

/* distorm insists on decoding a minimum of 15 instructions */
#define DISTORM_CNT   16

/*****************************************************************************/
/** 16-bit stuff **/

/* dis386 interface */
#pragma pack(1)
typedef struct
{
    SHORT  ilen;        /* Instruction length */
    LONG   rref;        /* Value of any IP relative storage reference */
    USHORT sel;         /* Selector of any CS:eIP storage reference.   */
    LONG   poff;        /* eIP value of any CS:eIP storage reference. */
    CHAR   longoper;    /* YES/NO value. Is instr in 32 bit operand mode? * */
    CHAR   longaddr;    /* YES/NO value. Is instr in 32 bit address mode? * */
    CHAR   buf[40];     /* String holding disassembled instruction * */
} *_Seg16 RETURN_FROM_DISASM;
#pragma pack()

typedef RETURN_FROM_DISASM (CDECL16 DISASM)(char* _Seg16 pSource,
                                            USHORT usIPvalue, USHORT usSegSize);

/** external function prototype **/
APIRET16 APIENTRY16 DOS16SIZESEG(USHORT Seg, ULONG* _Seg16 Size);

/*****************************************************************************/

/** global variables **/

FILE *          hTrap;
char            szModName[CCHMAXPATH];
char            szBuffer[1024];
char            bigBuf[2048];

/** local variables **/

static int      cTrapCount;
static PTIB     ptib;
static PPIB     ppib;
static ULONG    ulStartTime;
static char *   pStackTop;
static char     szFileName[CCHMAXPATH];

static XQ_DECODE          xd;
static RETURN_FROM_DISASM pDis386Data;
static _DecodedInst       diResults[DISTORM_CNT];

/*****************************************************************************/

/** formatting strings **/

static char *  pszTopLine =
  "\n______________________________________________________________________\n\n";

static char *  pszBotLine =
    "______________________________________________________________________\n\n";

static char *  pszFmtLine =
    " %s\n";

static char *  pszStackHdr =
    "   %3s     Address    Module     Obj:Offset    Nearest Public Symbol\n"
    " --------  ---------  --------  -------------  -----------------------\n";

static char *  pszRegEAX =
    " EAX : %08lX   EBX  : %08lX   ECX : %08lX   EDX  : %08lX\n";
static char *  pszRegESI =
    " ESI : %08lX   EDI  : %08lX\n";
static char *  pszRegESP =
    " ESP : %08lX   EBP  : %08lX   EIP : %08lX   EFLG : %08lX\n";
static char *  pszRegCS =
    " CS  : %04hX       CSLIM: %08lX   SS  : %04hX       SSLIM: %08lX\n";
static char *  pszRegDS =
    " DS  : %04hX       ES   : %04hX       FS  : %04hX       GS   : %04hX\n";

static char *  pszDupLine =
    " %08lX : %ld lines not printed duplicate the line above\n";


static char *  pszStackInfoHdr32 =
    "   Size       Base        ESP         Max         Top\n";
static char *  pszStackInfoHdr16 =
    "        Size       Base         SS:SP         Max          Top\n";
static char *  pszStackInfoNA =
    " %08lX   %08lX ->   N/A    -> %08lX -> %08lX\n";
static char *  pszStackInfo32 =
    " %08lX   %08lX -> %08lX -> %08lX -> %08lX\n";
static char *  pszStackInfo16 =
    " 16 : %08lX   %04hX:%04hX -> %04hX:%04hX -> %04hX:%04hX -> %04hX:%04hX\n";
static char *  pszStackInfo1632 =
    " 32 : %08lX   %08lX  -> %08lX  -> %08lX  -> %08lX\n";


/*****************************************************************************/

#if 0
#define XCPT_ACCESS_VIOLATION           0xC0000005
#define XCPT_IN_PAGE_ERROR              0xC0000006
#define XCPT_ILLEGAL_INSTRUCTION        0xC000001C
#define XCPT_INVALID_LOCK_SEQUENCE      0xC000001D
#define XCPT_NONCONTINUABLE_EXCEPTION   0xC0000024
#define XCPT_INVALID_DISPOSITION        0xC0000025
#define XCPT_BAD_STACK                  0xC0000027
#define XCPT_INVALID_UNWIND_TARGET      0xC0000028
#define XCPT_ARRAY_BOUNDS_EXCEEDED      0xC0000093
#define XCPT_INTEGER_DIVIDE_BY_ZERO     0xC000009B
#define XCPT_INTEGER_OVERFLOW           0xC000009C
#define XCPT_PRIVILEGED_INSTRUCTION     0xC000009D
#define XCPT_BREAKPOINT                 0xC000009F
#define XCPT_SINGLE_STEP                0xC00000A0
#define XCPT_FLOAT_DENORMAL_OPERAND     0xC0000094
#define XCPT_FLOAT_DIVIDE_BY_ZERO       0xC0000095
#define XCPT_FLOAT_INEXACT_RESULT       0xC0000096
#define XCPT_FLOAT_INVALID_OPERATION    0xC0000097
#define XCPT_FLOAT_OVERFLOW             0xC0000098
#define XCPT_FLOAT_STACK_CHECK          0xC0000099
#define XCPT_FLOAT_UNDERFLOW            0xC000009A
#define XCPT_B1NPX_ERRATA_02            0xC0010004
#endif

typedef struct {
  ULONG   ul;
  char *  psz;
} ULPSZ;

ULPSZ   xcpt[] =
  {
    {XCPT_ACCESS_VIOLATION,         "Access Violation"},
    {EXCEPTQ_DEBUG_EXCEPTION,       "Exceptq Debug Request"},
    {XCPT_IN_PAGE_ERROR,            "In Page Error"},
    {XCPT_ILLEGAL_INSTRUCTION,      "Illegal Instruction"},
    {XCPT_INVALID_LOCK_SEQUENCE,    "Invalid Lock Sequence"},
    {XCPT_NONCONTINUABLE_EXCEPTION, "Noncontinuable Exception"},
    {XCPT_INVALID_DISPOSITION,      "Invalid Disposition"},
    {XCPT_BAD_STACK,                "Bad Stack"},
    {XCPT_INVALID_UNWIND_TARGET,    "Invalid Unwind Target"},
    {XCPT_ARRAY_BOUNDS_EXCEEDED,    "Array Bounds Exceeded"},
    {XCPT_INTEGER_DIVIDE_BY_ZERO,   "Integer Divide By Zero"},
    {XCPT_INTEGER_OVERFLOW,         "Integer Overflow"},
    {XCPT_PRIVILEGED_INSTRUCTION,   "Privileged Instruction"},
    {XCPT_BREAKPOINT,               "Breakpoint"},
    {XCPT_FLOAT_DENORMAL_OPERAND,   "Float Denormal Operand"},
    {XCPT_FLOAT_DIVIDE_BY_ZERO,     "Float Divide By Zero"},
    {XCPT_FLOAT_INEXACT_RESULT,     "Float Inexact Result"},
    {XCPT_FLOAT_INVALID_OPERATION,  "Float Invalid Operation"},
    {XCPT_FLOAT_OVERFLOW,           "Float Overflow"},
    {XCPT_FLOAT_STACK_CHECK,        "Float Stack Check"},
    {XCPT_FLOAT_UNDERFLOW,          "Float Underflow"},
    {XCPT_B1NPX_ERRATA_02,          "B1NPX Errata 02"},
    {0x00000000,                    "Unknown Exception"}
  };

/*****************************************************************************/

/** local function prototypes **/

void    ReportException(EXCEPTIONREPORTRECORD* pExRepRec,
                        EXCEPTIONREGISTRATIONRECORD* pExRegRec,
                        CONTEXTRECORD* pCtxRec,
                        BOOL isDebug);
void    PrintReportHdr(void);
void    PrintReportFooter(void);
void    PrintException(EXCEPTIONREPORTRECORD* pExRepRec,
                       CONTEXTRECORD* pCtxRec);
BOOL    PrintTrapInfo(EXCEPTIONREPORTRECORD* pExRepRec,
                      CONTEXTRECORD* pCtxRec);
void    PrintCause(EXCEPTIONREPORTRECORD* pExRepRec);
void    PrintDebugInfo(EXCEPTIONREPORTRECORD* pExRepRec);

void    PrintDisassembly(CONTEXTRECORD* pCtxRec);
BOOL    SetDecodeLimits(CONTEXTRECORD* pCtxRec);
BOOL    PrintDis386Disassembly(PFN pfn);
BOOL    PrintDistormDisassembly(PFN pfn);
PFN     LoadDisassemblerDll(char* pszMod, ULONG ulOrd, char* pszProc);

void    PrintRegisters(CONTEXTRECORD* pCtxRec);
void    GetMemoryAttributes(ULONG ulAddress, char* pBuf);
void    Print16BitRegInfo(CONTEXTRECORD* pCtxRec);

void    PrintStackInfo(CONTEXTRECORD* pCtxRec);
void    PrintCallStack(EXCEPTIONREPORTRECORD* pExRepRec,
                       CONTEXTRECORD* pCtxRec);
char*   GetValidStackTop(void);
void    PrintLabelsOnStack(CONTEXTRECORD* pCtxRec);
void    PrintStackDump(CONTEXTRECORD* pCtxRec);

void    PrintRegisterPointers(CONTEXTRECORD* pCtxRec);
void    PrintMemoryAt(char* pMem, PSZ pszDesc, ULONG flags);
void    PrintMemory(char* pMem, ULONG cbMem, ULONG flags);
void    PrintMemoryLine(char* pSrc, ULONG cbSrc, ULONG flags);
void    PrintMemoryHdr(ULONG flags);

void    PrintDlls(void);
void    WalkStack(void* pvStackBottom, void* pvStackTop,
                  ULONG ulEBP, USHORT usSS, ULONG ulEIP, USHORT usCS);
void    TimedBeep(void);

/*****************************************************************************/
/* Print exception report                                                    */
/*****************************************************************************/

void    ReportException(EXCEPTIONREPORTRECORD* pExRepRec,
                        EXCEPTIONREGISTRATIONRECORD* pExRegRec,
                        CONTEXTRECORD* pCtxRec,
                        BOOL isDebug)
{
  ULONG     ulNest;

  /* Perform initialization if cTrapCount is zero (i.e. the app trapped). */
  if (!cTrapCount) {
    DosEnterMustComplete(&ulNest);
    cTrapCount++;

    /* Exit if the option to disable exceptq reporting is set. */
    InitOptions(NULL, NULL);
    if (!fReport) {
      DosUnsetExceptionHandler(pExRegRec);
      cTrapCount--;
      DosExitMustComplete(&ulNest);
      return;
    }

    if (isDebug && !fDebug) {
      cTrapCount--;
      DosExitMustComplete(&ulNest);
      return;
    }

    DosError(FERR_DISABLEEXCEPTION | FERR_DISABLEHARDERR);
    DosQuerySysInfo(QSV_MS_COUNT, QSV_MS_COUNT,
                    &ulStartTime, sizeof(ulStartTime));
    TimedBeep();
    DosGetInfoBlocks(&ptib, &ppib);

    sprintf(szFileName, "%04lX_%02lX.TRP",
            ppib->pib_ulpid, ptib->tib_ptib2->tib2_ultid);
    fprintf(stderr, "Creating %s\n", szFileName);

    hTrap = fopen(szFileName, "a");
    if (!hTrap) {
      fprintf(stderr, "Can not append to %s - writing to stdout\n", szFileName);
      hTrap = stdout;
    }
    setbuf(hTrap, NULL);
  }

  /* If cTrapCount is not zero we're here because exceptq trapped. */
  else {
    /* Prevent exceptq from handling any subsequent traps. */
    DosUnsetExceptionHandler(pExRegRec);
    cTrapCount++;

    /* Prevent debug exceptions from trying to continue execution. */
    if (isDebug)
      pExRepRec->fHandlerFlags |= EH_NONCONTINUABLE;

    /* Try to get output somewhere */
    if (!hTrap) {
      hTrap = stderr;
      setbuf(hTrap, NULL);
    }
    if (hTrap != stderr)
      fputs("\n ** Exceptq trapped **\n", stderr);

    fputs(pszTopLine, hTrap);
    if (pCtxRec->ContextFlags & CONTEXT_CONTROL)
      fprintf(hTrap, " ** Exception handler trapped at %04hX:%08lX **\n",
              LOUSHORT(pCtxRec->ctx_SegCs), pCtxRec->ctx_RegEip);
    else
      fputs(" ** Exception handler trapped at unknown address **\n", hTrap);
    fputs(pszBotLine, hTrap);
  }

  /* Print Report */
  PrintReportHdr();
  PrintException(pExRepRec, pCtxRec);
  PrintRegisters(pCtxRec);
  PrintStackInfo(pCtxRec);
  PrintCallStack(pExRepRec, pCtxRec);
  PrintLabelsOnStack(pCtxRec);
  PrintStackDump(pCtxRec);
  PrintRegisterPointers(pCtxRec);
  PrintDlls();
  PrintReportFooter();

  /* Shut Down */
  CloseSymbolFiles();
  if (hTrap != stdout && hTrap != stderr)
    fclose(hTrap);
  if (fBeep)
    DosBeep(440, 60);

  /* Unset the handler for fatal exceptions but not for debug exceptions. */
  if (isDebug)
    cTrapCount--;
  else
    DosUnsetExceptionHandler(pExRegRec);

  DosExitMustComplete(&ulNest);

  return;
}

/*****************************************************************************/
/*  The 'Exception Report' & 'End of exception report' sections              */
/*****************************************************************************/

void    PrintReportHdr(void)
{
  DATETIME  dt;
  ULONG     aul[2];

  TimedBeep();

  /* section header with date & time */
  fputs(pszTopLine, hTrap);
  fflush(hTrap);

  DosGetDateTime(&dt);
  fprintf(hTrap, " Exception Report - created %04hd/%02hd/%02hd %02hd:%02hd:%02hd\n",
          (USHORT)dt.year, (USHORT)dt.month, (USHORT)dt.day,
          (USHORT)dt.hours, (USHORT)dt.minutes, (USHORT)dt.seconds);
  fputs(pszBotLine, hTrap);

  /* app info string - skip if not present */
  if (fReportInfo) {
    fprintf(hTrap, pszFmtLine, szReportInfo);
    fputs("\n", hTrap);
  }

  /* version - always print something */
  if (DosQuerySysInfo(QSV_VERSION_MAJOR, QSV_VERSION_MINOR,
                      aul, sizeof(aul))) {
    aul[0] = 0;
    aul[1] = 0;
  }
  fprintf(hTrap, " OS2/eCS Version:  %ld.%ld\n", aul[0] / 10, aul[1]);

  /* nbr of processors - skip if not supported */
  if (!DosQuerySysInfo(QSV_NUMPROCESSORS, QSV_NUMPROCESSORS,
                      &aul[0], sizeof(aul[0])))
    fprintf(hTrap, " # of Processors:  %ld\n", aul[0]);

  /* physical memory - always print something */
  if (DosQuerySysInfo(QSV_TOTPHYSMEM, QSV_TOTPHYSMEM,
                      &aul[0], sizeof(aul[0])))
    aul[0] = 0;
  fprintf(hTrap, " Physical Memory:  %ld mb\n", aul[0] / 0x100000);

  /* virtual address limit - skip if not supported */
  if (!DosQuerySysInfo(QSV_VIRTUALADDRESSLIMIT, QSV_VIRTUALADDRESSLIMIT,
                      &aul[0], sizeof(aul[0])))
    fprintf(hTrap, " Virt Addr Limit:  %ld mb\n", aul[0]);

  /* Exceptq version & build date */
  fprintf(hTrap, " Exceptq Version:  %s (%s)\n",
          EXCEPTQ_VERSION, __DATE__);

  return;
}

/*****************************************************************************/

void    PrintReportFooter(void)
{
  ULONG    ulEnd;

  DosQuerySysInfo(QSV_MS_COUNT, QSV_MS_COUNT, &ulEnd, sizeof(ulEnd));

  fputs(pszTopLine, hTrap);
  fprintf(hTrap, " End of Exception Report - report took %ld ms to generate\n",
          ulEnd - ulStartTime);
  fputs(pszBotLine, hTrap);

  return;
}

/*****************************************************************************/
/*  The 'Exception' section                                                  */
/*****************************************************************************/

void    PrintException(EXCEPTIONREPORTRECORD* pExRepRec,
                       CONTEXTRECORD* pCtxRec)
{
  ULPSZ *   pxcpt = xcpt;

  if (DosQueryModuleName(ppib->pib_hmte, CCHMAXPATH, szFileName))
    strcpy(szFileName, "N/A");

  while (pxcpt->ul && pxcpt->ul != pExRepRec->ExceptionNum)
    pxcpt++;

  fputs(pszTopLine, hTrap);
  fprintf(hTrap, " Exception %08lX - %s\n",
          pExRepRec->ExceptionNum, pxcpt->psz);
  fputs(pszBotLine, hTrap);

  fprintf(hTrap, " Process:  %s\n", szFileName);
  fprintf(hTrap, " PID:      %02lX (%lu)\n",
          ppib->pib_ulpid, ppib->pib_ulpid);
  fprintf(hTrap, " TID:      %02lX (%lu)\n",
          ptib->tib_ptib2->tib2_ultid, ptib->tib_ptib2->tib2_ultid);

  if (verbosity > XQ_CONCISE)
    fprintf(hTrap, " Slot:     %02lX (%lu)\n",
            ptib->tib_ordinal, ptib->tib_ordinal);

  fprintf(hTrap, " Priority: %lX\n",
          ptib->tib_ptib2->tib2_ulpri);
  fputs("\n", hTrap);

  if (PrintTrapInfo(pExRepRec, pCtxRec))
    PrintDisassembly(pCtxRec);

  return;
}

/*****************************************************************************/

BOOL    PrintTrapInfo(EXCEPTIONREPORTRECORD* pExRepRec,
                      CONTEXTRECORD* pCtxRec)
{
  APIRET    rc;
  ULONG     ulObjNum;
  ULONG     ulOffset;
  HMODULE   hMod;

  TimedBeep();

  /* If the module can't be identified, print some dummy lines then exit. */
  if (DosQueryModFromEIP(&hMod, &ulObjNum, CCHMAXPATH,
                         szModName, &ulOffset,
                         (ULONG)pExRepRec->ExceptionAddress)) {
    if (verbosity > XQ_CONCISE)
      fputs(" Module:   N/A\n", hTrap);
    fputs(" Filename: N/A\n", hTrap);

    fprintf(hTrap, " Cause:    Invalid execution address %08lX\n",
            (ULONG)pExRepRec->ExceptionAddress);

    return FALSE;
  }
  ulObjNum++;

  if (verbosity > XQ_CONCISE)
    fprintf(hTrap, " Module:   %s\n", szModName);

  rc = DosQueryModuleName(hMod, CCHMAXPATH, szFileName);
  fprintf(hTrap, " Filename: %s\n", (rc ? szModName : szFileName));

  /* If the control registers are available, use them;
   * Otherwise, print the failing address.
   */
  if (~pCtxRec->ContextFlags & CONTEXT_CONTROL)
    fprintf(hTrap, " Address:  %08lX (%04lX:%08lX)\n",
            (ULONG)pExRepRec->ExceptionAddress, ulObjNum, ulOffset);
  else
  if (LOUSHORT(pCtxRec->ctx_SegCs) == FLATCS || pCtxRec->ctx_RegEip > 0x00010000)
    fprintf(hTrap, " Address:  %04hX:%08lX (%04lX:%08lX)\n",
            LOUSHORT(pCtxRec->ctx_SegCs), pCtxRec->ctx_RegEip, ulObjNum, ulOffset);
  else 
    fprintf(hTrap, " Address:  %04hX:%04lX (%04lX:%08lX)\n",
            LOUSHORT(pCtxRec->ctx_SegCs), pCtxRec->ctx_RegEip, ulObjNum, ulOffset);

  if (pExRepRec->ExceptionNum == XCPT_ACCESS_VIOLATION)
    PrintCause(pExRepRec);
  else
  if (pExRepRec->ExceptionNum == EXCEPTQ_DEBUG_EXCEPTION)
    PrintDebugInfo(pExRepRec);

  return (~pCtxRec->ContextFlags & CONTEXT_CONTROL) ? FALSE : TRUE;
}

/*****************************************************************************/

void    PrintCause(EXCEPTIONREPORTRECORD* pExRepRec)
{
  *szBuffer = 0;

  switch (pExRepRec->ExceptionInfo[0]) {
    case XCPT_READ_ACCESS:
      sprintf(bigBuf, "Attempted to read from %08lX",
              pExRepRec->ExceptionInfo[1]);
      GetMemoryAttributes(pExRepRec->ExceptionInfo[1], szBuffer);
      break;
    case XCPT_WRITE_ACCESS:
      sprintf(bigBuf, "Attempted to write to %08lX",
              pExRepRec->ExceptionInfo[1]);
      GetMemoryAttributes(pExRepRec->ExceptionInfo[1], szBuffer);
      break;
    case XCPT_EXECUTE_ACCESS:
      sprintf(bigBuf, "Attempted to execute at %08lX",
              pExRepRec->ExceptionInfo[1]);
      GetMemoryAttributes(pExRepRec->ExceptionInfo[1], szBuffer);
      break;
    case XCPT_SPACE_ACCESS:
      /* It looks like this is off by one... - fixme to know why */
      sprintf(bigBuf, "Attempted to access beyond selector %08lX limit",
              pExRepRec->ExceptionInfo[1] ?
              pExRepRec->ExceptionInfo[1] + 1 : 0);
      break;
    case XCPT_LIMIT_ACCESS:
      strcpy(bigBuf, "Limit access fault");
      break;
    case XCPT_UNKNOWN_ACCESS:
      strcpy(bigBuf, "Unknown access fault");
      break;
    default:
      strcpy(bigBuf, "Other unknown access fault");
  }

  fprintf(hTrap, " Cause:    %s\n", bigBuf);
  if (*szBuffer)
    fprintf(hTrap, "           (%s)\n", szBuffer);

  return;
}

/*****************************************************************************/

void    PrintDebugInfo(EXCEPTIONREPORTRECORD* pExRepRec)
{
  int   ctr;

  fprintf(hTrap, " Cause:    Program requested an Exceptq debug report\n");

  if (!pExRepRec->cParameters ||
      pExRepRec->cParameters > EXCEPTION_MAXIMUM_PARAMETERS)
    return;

  fputs(" Debug:    ", hTrap);

  if (pExRepRec->ExceptionInfo[0])
    vfprintf(hTrap, (char*)pExRepRec->ExceptionInfo[0], (char*)&pExRepRec->ExceptionInfo[1]);
  else {
    for (ctr = 1; ctr < pExRepRec->cParameters; ctr++) {
      fprintf(hTrap, "[%d]= %08lx  ", ctr, pExRepRec->ExceptionInfo[ctr]);
    }
  }

  fputs("\n", hTrap);

  return;
}

/*****************************************************************************/

void    PrintDisassembly(CONTEXTRECORD* pCtxRec)
{
  PFN     pfn;

  if (verbosity < XQ_TERSE)
    return;

  TimedBeep();

  pfn = LoadDisassemblerDll("DISTORM", 0, "distorm_decode32");
  if (pfn) {
    if (!SetDecodeLimits(pCtxRec) ||
        !PrintDistormDisassembly(pfn))
      fputs(" Code:     failing instruction can not be disassembled\n", hTrap);
    return;
  }

  pfn = LoadDisassemblerDll("DIS386", 1, 0);
  if (pfn) {
    if (!SetDecodeLimits(pCtxRec) ||
        !PrintDis386Disassembly(pfn))
      fputs(" Code:     failing instruction can not be disassembled\n", hTrap);
    return;
  }

  fputs(" Code:     disassembler dll not available (distorm or dis386)\n", hTrap);

  return;
}

/*****************************************************************************/

BOOL    SetDecodeLimits(CONTEXTRECORD* pCtxRec)
{
  void *    pv32;
  ULONG     ulAttr;
  ULONG     ulLimit;

  TimedBeep();

  memset(&xd, 0, sizeof(XQ_DECODE));

  /* Set the number of instructions to display before & after the one
   * that trapped, plus the number of bytes to decode before & after.
  */
  if (verbosity < XQ_CONCISE) {
    xd.bytesBefore = 0;
    xd.codeBefore = 0;
    xd.codeAfter = 0;
  }
  else {
    xd.bytesBefore = 80;
    xd.codeBefore = 4;
    xd.codeAfter = 3;
  }
  xd.bytesAfter = 64;

  /* 32-bit code */
  if (LOUSHORT(pCtxRec->ctx_SegCs) == FLATCS || pCtxRec->ctx_RegEip > 0x00010000) {
    xd.addr32 = pCtxRec->ctx_RegEip;
    pv32 = (void*)xd.addr32;
  }
  /* 16-bit code - use an explicit thunk to get a flat address */
  else {
    xd.seg16 = LOUSHORT(pCtxRec->ctx_SegCs);
    xd.addr16 = (USHORT)pCtxRec->ctx_RegEip;
    xd.addr32 = ((LOUSHORT(pCtxRec->ctx_SegCs) & ~7) << 13) | pCtxRec->ctx_RegEip;
    pv32 = (void*)xd.addr32;
  }

  /* confirm that the trapping address & the X bytes after it are valid */
  if (DosQueryMem(pv32, &xd.bytesAfter, &ulAttr) ||
      (ulAttr & (PAG_READ | PAG_EXECUTE)) != (PAG_READ | PAG_EXECUTE))
    return FALSE;

  /* If the address is LT 80 bytes from the start of the segment,
   * reduce the bytes-before figure so we'll start at offset 0.
  /*
  if ((ulAttr & PAG_BASE) && (xd.addr32 & ~0xfff) < xd.bytesBefore)
    xd.bytesBefore = xd.addr32 & ~0xfff;

  /* For 16-bit code, ensure that the EIP lies within the segment,
   * and reduce the bytes-after figure if it exceeds the seg's limit.
  */
  if (xd.seg16) {
    if (DOS16SIZESEG(xd.seg16, &ulLimit) || xd.addr16 >= ulLimit)
      return FALSE;

    if (xd.addr16 + xd.bytesAfter > ulLimit)
      xd.bytesAfter = ulLimit - xd.addr16;
  }

  return TRUE;
}

/*****************************************************************************/

BOOL    PrintDis386Disassembly(PFN pfn)
{
  void *  pv32;

  TimedBeep();

  if (xd.seg16) {
    pDis386Data = ((DISASM*)pfn)(MAKE16P(xd.seg16, xd.addr16),
                                 xd.addr16, FALSE);
  }
  else {
    if (DosAllocMem(&pv32, xd.bytesAfter, PAG_READ | PAG_WRITE | PAG_COMMIT))
      return FALSE;

    memcpy(pv32, (void*)xd.addr32, xd.bytesAfter);
    pDis386Data = ((DISASM*)pfn)(pv32, (USHORT)pv32, TRUE);
    DosFreeMem(pv32);
  }

  fprintf(hTrap, " Code:     %s\n", pDis386Data->buf);

  return TRUE;
}

/*****************************************************************************/

BOOL    PrintDistormDisassembly(PFN pfn)
{
  ULONG     decode;
  ULONG     used;
  ULONG     ndx;
  ULONG     stop;
  ULONG     mneLth;
  ULONG     opLth;
  _DecodeType   dt;

  TimedBeep();

  /* Decode until the trapping address appears as the last instruction decoded,
   * or until the decode address is the trapping address.  With each iteration,
   * reduce the bytes decoded so the high-end limit is never exceeded.
   */

  dt = xd.seg16 ? Decode16Bits : Decode32Bits;
  xd.bytesBefore++;
  decode = xd.addr32 - xd.bytesBefore;

  do {
    xd.bytesBefore--;
    decode++;

    if (((DISTORM_DECODE32*)pfn)(decode, (char*)decode,
                                 xd.bytesBefore + xd.bytesAfter, dt,
                                 diResults, DISTORM_CNT, (UINT*)&used)
        == DECRES_INPUTERR)
      return FALSE;

    if (!used)
      continue;

    /* If we started close to the beginning of the segment, the disassembler
     * may have decoded beyond the desired instruction.  If so, look for the
     * desired address and make it look like the last instruction decoded.
     * If it isn't found, then the decoder is out of sync, so we'll continue.
     */
    if (diResults[used-1].offset > xd.addr32) {
      for (ndx = 0; ndx < used; ndx++) {
        if (diResults[ndx].offset == xd.addr32) {
          used = ndx + 1;
          break;
        }
      }
    }

    /* If the last instruction decoded is the one we want, exit the loop. */
    if (diResults[used-1].offset == xd.addr32)
      break;

  } while (decode < xd.addr32);

  if (!used)
    return FALSE;

  /* Prepare for the final decode.  Go back codeBefore entries
   * (if there are that many) and use its offset as the starting
   * address.  Calculate the number of bytes-before to decode.
   */
  if (xd.codeBefore >= used)
    xd.codeBefore = used - 1;
  decode = diResults[used - 1 - xd.codeBefore].offset;
  xd.bytesBefore = diResults[used - 1].offset - decode;

  TimedBeep();

  if (((DISTORM_DECODE32*)pfn)(decode, (char*)decode,
                               xd.bytesBefore + xd.bytesAfter, dt,
                               diResults, DISTORM_CNT, (UINT*)&used)
      == DECRES_INPUTERR || !used)
    return FALSE;

  /* Set the index where the display should stop to the trap's entry
   * plus codeAfter entries but don't print more info that we have.
   */
  stop = xd.codeBefore + xd.codeAfter + 1;
  if (stop > used)
    stop = used;

  /* Determine the maximum widths of the mnemonic and operand
   * strings so we can format the display into tidy little columns.
   */
  mneLth = 0;
  opLth = 0;
  for (ndx = 0; ndx < stop; ndx++) {
    if (diResults[ndx].mnemonic.length > mneLth)
      mneLth = diResults[ndx].mnemonic.length;
    if (diResults[ndx].operands.length > opLth)
      opLth = diResults[ndx].operands.length;
  }

  fputs(pszTopLine, hTrap);
  fputs(" Failing Instruction\n", hTrap);
  fputs(pszBotLine, hTrap);

  /* Finally!  We have something to print. */
  for (ndx = 0; ndx < stop; ndx++) {
    if (xd.seg16)
      sprintf(szBuffer, " %04hX:%04hX",
              xd.seg16, LOUSHORT(diResults[ndx].offset));
    else
      sprintf(szBuffer, " %08X ", diResults[ndx].offset);

    fprintf(hTrap, "%s%c%-*s %-*s  (%s)\n",
            szBuffer,
            (diResults[ndx].offset == xd.addr32 ? '>' : ' '),
            mneLth, diResults[ndx].mnemonic.p,
            opLth, diResults[ndx].operands.p,
            diResults[ndx].instructionHex.p);
  }

  return TRUE;
}

/*****************************************************************************/
/* Load a dll, then retrieve a proc address by name or ordinal.
 * pszMod must be just the module name (preferably uppercased).
 * pszProc must be null (not a null string) if loading by ordinal.
 * ulOrd must be zero if loading by proc name.
*/

PFN     LoadDisassemblerDll(char* pszMod, ULONG ulOrd, char* pszProc)
{
  ULONG     seg;
  ULONG     offs;
  HMODULE   hMod;
  PFN       pfn = 0;
  char *    ptr;

  /* See if the dll can be found along the path.
   * If not, see if it's in the same directory as exceptq.dll.
   */
  if (DosLoadModule(szBuffer, CCHMAXPATH, pszMod, &hMod)) {

    if (DosQueryModFromEIP(&hMod, &seg, CCHMAXPATH, szBuffer,
                           &offs, (ULONG)&LoadDisassemblerDll) ||
        DosQueryModuleName(hMod, CCHMAXPATH, szBuffer) ||
        (ptr = strrchr(szBuffer, '\\')) == 0)
      return 0;

    strcpy(ptr + 1, pszMod);
    strcat(szBuffer, ".DLL");
    if (DosLoadModule(&szBuffer[CCHMAXPATH], CCHMAXPATH, szBuffer, &hMod))
      return 0;
  }

  /* If the proc address can't be retrieved, unload the dll. */
  if (DosQueryProcAddr(hMod, ulOrd, pszProc, &pfn))
    DosFreeModule(hMod);

  return pfn;
}

/*****************************************************************************/
/*  The 'Registers' section                                                  */
/*****************************************************************************/

void    PrintRegisters(CONTEXTRECORD* pCtxRec)
{
  APIRET16  rc16;
  ULONG     ulSize;
  ULONG     ulCSSize;

  TimedBeep();

  fputs(pszTopLine, hTrap);
  fputs(" Registers\n", hTrap);
  fputs(pszBotLine, hTrap);

  if (pCtxRec->ContextFlags & CONTEXT_INTEGER) {
    fprintf(hTrap, pszRegEAX,
            pCtxRec->ctx_RegEax, pCtxRec->ctx_RegEbx,
            pCtxRec->ctx_RegEcx, pCtxRec->ctx_RegEdx);

    fprintf(hTrap, pszRegESI,
            pCtxRec->ctx_RegEsi, pCtxRec->ctx_RegEdi);
  }

  if (pCtxRec->ContextFlags & CONTEXT_CONTROL) {
    rc16 = DOS16SIZESEG(LOUSHORT(pCtxRec->ctx_SegCs), &ulCSSize);
    if (rc16) {
      if (LOUSHORT(pCtxRec->ctx_SegCs) == FLATCS)
        ulCSSize = 0xFFFFFFFFL;
      else
        ulCSSize = 0;
    }

    rc16 = DOS16SIZESEG(LOUSHORT(pCtxRec->ctx_SegSs), &ulSize);
    if (rc16) {
      if (LOUSHORT(pCtxRec->ctx_SegSs) == FLATDS)
        ulSize = 0xFFFFFFFFL;
      else
        ulSize = 0;
    }

    fprintf(hTrap, pszRegESP,
            pCtxRec->ctx_RegEsp, pCtxRec->ctx_RegEbp,
            pCtxRec->ctx_RegEip, pCtxRec->ctx_EFlags);

    fprintf(hTrap, pszRegCS,
            LOUSHORT(pCtxRec->ctx_SegCs), ulCSSize,
            LOUSHORT(pCtxRec->ctx_SegSs), ulSize);
  }

  if (pCtxRec->ContextFlags & CONTEXT_SEGMENTS) {
    fprintf(hTrap, pszRegDS,
            LOUSHORT(pCtxRec->ctx_SegDs), LOUSHORT(pCtxRec->ctx_SegEs),
            LOUSHORT(pCtxRec->ctx_SegFs), LOUSHORT(pCtxRec->ctx_SegGs));
  }

  if (verbosity >= XQ_CONCISE &&
      pCtxRec->ContextFlags & CONTEXT_CONTROL) {
    fputs("\n", hTrap);

    if (LOUSHORT(pCtxRec->ctx_SegDs) == FLATDS) {
      GetMemoryAttributes(pCtxRec->ctx_RegEax, szBuffer);
      fprintf(hTrap, " EAX : %s\n", szBuffer);
      GetMemoryAttributes(pCtxRec->ctx_RegEbx, szBuffer);
      fprintf(hTrap, " EBX : %s\n", szBuffer);
      GetMemoryAttributes(pCtxRec->ctx_RegEcx, szBuffer);
      fprintf(hTrap, " ECX : %s\n", szBuffer);
      GetMemoryAttributes(pCtxRec->ctx_RegEdx, szBuffer);
      fprintf(hTrap, " EDX : %s\n", szBuffer);
      GetMemoryAttributes(pCtxRec->ctx_RegEsi, szBuffer);
      fprintf(hTrap, " ESI : %s\n", szBuffer);
      GetMemoryAttributes(pCtxRec->ctx_RegEdi, szBuffer);
      fprintf(hTrap, " EDI : %s\n", szBuffer);
    }
    else
      Print16BitRegInfo(pCtxRec);
  }

  return;
}

/*****************************************************************************/
/* Identify memory attributes & ownership */

void    GetMemoryAttributes(ULONG ulAddress, char* pBuf)
{
  ULONG     ul;
  ULONG     ulAttr;
  ULONG     ulObjNum;
  ULONG     ulOffset;
  char *    ptr;

  ul = 1;
  if (DosQueryMem((void*)ulAddress, &ul, &ulAttr)) {
    strcpy(pBuf, "not a valid address");
    return;
  }
  if (ulAttr & PAG_FREE) {
    strcpy(pBuf, "unallocated memory");
    return;
  }

  /* Identify attributes */
  if (~ulAttr & PAG_COMMIT)
    ptr = "uncommitted";
  else
  if (ulAttr & PAG_EXECUTE) {
    if (ulAttr & PAG_READ)
      ptr = "read/exec ";
    else
      ptr = "executable";
  }
  else
  if (ulAttr & PAG_WRITE)
    ptr = "read/write";
  else
    ptr = "read-only ";

  if (ulAddress <  (ULONG)ptib->tib_pstacklimit &&
      ulAddress >= (ULONG)ptib->tib_pstack) {
    sprintf(pBuf, "%s memory on this thread's stack", ptr);
    return;
  }

  /* Round the address down to the base page so we get the correct owner
   * for the segment containing the address.  For low memory, it's the
   * previous 64k boundary;  for high mem, it's the previous 4k boundary.
   */
  if (ulAddress >= 0x20000000)
    ul = ulAddress & 0xFFFFF000;
  else
    ul = ulAddress & 0xFFFF0000;

  if (DosQueryModFromEIP(&ulAttr, &ulObjNum, CCHMAXPATH,
                         szModName, &ulOffset, ul)) {
    sprintf(pBuf, "%s memory - owner unknown", ptr);
  }
  else {
    /* -1 usually(?) means memory allocated by a module */
    if (ulObjNum == (ULONG)-1)
      sprintf(pBuf, "%s memory allocated by %s", ptr, szModName);
    else
      /* This is one of the module's segments. */
      sprintf(pBuf, "%s memory at %04lX:%08lX in %s",
              ptr, ulObjNum + 1, ulOffset + (ulAddress & 0xFFFF), szModName);
  }
  return;
}

/*****************************************************************************/

void    Print16BitRegInfo(CONTEXTRECORD* pCtxRec)
{
  APIRET16  rc16;
  ULONG     ulSize;

  rc16 = DOS16SIZESEG(LOUSHORT(pCtxRec->ctx_SegDs), &ulSize);
  if (!rc16) {
    if ((USHORT)ulSize < (USHORT)pCtxRec->ctx_RegEsi)
      fputs(" DS:SI points outside Data Segment\n", hTrap);
    else
      fputs(" DS:SI is a valid source\n", hTrap);
  }
  else {
    if (LOUSHORT(pCtxRec->ctx_SegDs) == FLATDS)
      fputs(" DS is a 32-bit selector\n", hTrap);
    else
      fputs(" DS is invalid\n", hTrap);
  }

  rc16 = DOS16SIZESEG(LOUSHORT(pCtxRec->ctx_SegEs), &ulSize);
  if (!rc16) {
    if ((USHORT)ulSize < (USHORT)pCtxRec->ctx_RegEdi)
      fputs(" ES:DI points outside Extra Segment\n", hTrap);
    else
      fputs(" ES:DI is a valid destination\n", hTrap);
  }
  else {
    if (LOUSHORT(pCtxRec->ctx_SegEs) == FLATDS)
      fputs(" ES is a 32-bit selector\n", hTrap);
    else
      fputs(" ES is invalid\n", hTrap);
  }

  return;
}

/*****************************************************************************/
/*  The 'Call Stack' section                                                 */
/*****************************************************************************/

void    PrintCallStack(EXCEPTIONREPORTRECORD* pExRepRec,
                       CONTEXTRECORD* pCtxRec)
{
  ULONG     ulEIP;
  ULONG     ulEBP;
  USHORT    usCS;
  USHORT    usSS;

  TimedBeep();

  if (pCtxRec->ContextFlags & CONTEXT_CONTROL) {
    ulEIP = pCtxRec->ctx_RegEip;
    usCS = LOUSHORT(pCtxRec->ctx_SegCs);
    ulEBP = pCtxRec->ctx_RegEbp;
    usSS = LOUSHORT(pCtxRec->ctx_SegSs);
  }
  else {
    /* fixme to guess better */
    ulEIP = (ULONG)pExRepRec->ExceptionAddress,
    usCS = 0;
    ulEBP = (ULONG)ptib->tib_pstack;
    usSS = 0;
  }

  fputs(pszTopLine, hTrap);
  fputs(" Call Stack\n", hTrap);
  fputs(pszBotLine, hTrap);

  /* fixme to bypass if insufficient context */
  WalkStack(ptib->tib_pstack, ptib->tib_pstacklimit,
            ulEBP, usSS, ulEIP, usCS);

  return;
}

/*****************************************************************************/
/*  The 'Stack Info' section                                                 */
/*****************************************************************************/

void    PrintStackInfo(CONTEXTRECORD* pCtxRec)
{
  TimedBeep();

  pStackTop = GetValidStackTop();

  fputs(pszTopLine, hTrap);
  fprintf(hTrap, " Stack Info for Thread %02lX\n", ptib->tib_ptib2->tib2_ultid);
  fputs(pszBotLine, hTrap);

  if (~pCtxRec->ContextFlags & CONTEXT_CONTROL) {
    fputs(pszStackInfoHdr32, hTrap);
    fprintf(hTrap, pszStackInfoNA,
            (ULONG)ptib->tib_pstacklimit - (ULONG)ptib->tib_pstack,
            ptib->tib_pstacklimit, pStackTop, ptib->tib_pstack);

    pStackTop = 0;
    fprintf(hTrap, "\n Stack can not be accessed: control context is not available\n");
  }
  else {
    if (LOUSHORT(pCtxRec->ctx_SegSs) == FLATDS) {
      fputs(pszStackInfoHdr32, hTrap);
      fprintf(hTrap, pszStackInfo32,
              (ULONG)ptib->tib_pstacklimit - (ULONG)ptib->tib_pstack,
              ptib->tib_pstacklimit, pCtxRec->ctx_RegEsp,
              pStackTop, ptib->tib_pstack);
    }
    else {
      #define XQ_F2S(addr, sel)  (USHORT)(((((ULONG)(addr)) >> 13) & ~7) | (((ULONG)(sel)) & 7))

      fputs(pszStackInfoHdr16, hTrap);
      fprintf(hTrap, pszStackInfo16,
              (ULONG)ptib->tib_pstacklimit - (ULONG)ptib->tib_pstack,
              XQ_F2S(ptib->tib_pstacklimit, pCtxRec->ctx_SegSs),
              LOUSHORT(ptib->tib_pstacklimit),
              LOUSHORT(pCtxRec->ctx_SegSs),
              LOUSHORT(pCtxRec->ctx_RegEsp),
              XQ_F2S(pStackTop, pCtxRec->ctx_SegSs),
              LOUSHORT(pStackTop),
              XQ_F2S(ptib->tib_pstack, pCtxRec->ctx_SegSs),
              LOUSHORT(ptib->tib_pstack));
      fprintf(hTrap, pszStackInfo1632,
              (ULONG)ptib->tib_pstacklimit - (ULONG)ptib->tib_pstack,
              ptib->tib_pstacklimit,
              ((LOUSHORT(pCtxRec->ctx_SegSs) & ~7) << 13) | LOUSHORT(pCtxRec->ctx_RegEsp),
              pStackTop, ptib->tib_pstack);
    }

    if (pStackTop > (char*)ptib->tib_pstacklimit) {
      pStackTop = 0;
      fprintf(hTrap, "\n Stack can not be accessed: stack ptr appears to be invalid\n");
    }
  }

  return;
}

/*****************************************************************************/
/* Starting at the base of the stack (i.e. the highest address) minus 4kb,
 * look for the page with the lowest address whose memory is committed.
 * Somewhere in that page is the furthest the stack ever grew.  If anyone
 * were interested, we could search for the lowest non-zero dword and
 * reasonably claim that it was the historical top of the stack.
 */

char*   GetValidStackTop(void)
{
  APIRET    rc;
  ULONG     ulSize;
  ULONG     ulState;
  char *    pStackPtr;

  TimedBeep();

  /* Find accessible stack range */
  for (pStackPtr = ((char*)ptib->tib_pstacklimit - 0x1000);
       pStackPtr >= (char*)ptib->tib_pstack;
       pStackPtr -= 0x1000) {
    ulSize = 0x1000;
    rc = DosQueryMemState(pStackPtr, &ulSize, &ulState);
    if (rc || ~ulState & PAG_PRESENT) {
      break;
    }
  }
  pStackPtr += 0x1000;

  return pStackPtr;
}

/*****************************************************************************/
/*  The 'Labels on the Stack' section                                        */
/*****************************************************************************/

void    PrintLabelsOnStack(CONTEXTRECORD* pCtxRec)
{
  APIRET    rc;
  ULONG     ul;
  ULONG     ulSize;
  ULONG     ulAttr;
  ULONG     ulObjNum;
  ULONG     ulOffset;
  HMODULE   hMod;
  char*     pStackPtr;

  TimedBeep();

  if (verbosity < XQ_TERSE || !pStackTop)
    return;

  fputs(pszTopLine, hTrap);
  fputs(" Labels on the Stack\n", hTrap);
  fputs(pszBotLine, hTrap);

  fprintf(hTrap, pszStackHdr, "ESP");

  pStackPtr = pStackTop;

  /* Optimize start location */
  if ((pCtxRec->ctx_RegEbp & 0x3) == 0 &&
      pCtxRec->ctx_RegEbp > (ULONG)pStackPtr &&
      (void*)pCtxRec->ctx_RegEbp < ptib->tib_pstacklimit) {
    pStackPtr = (char*)pCtxRec->ctx_RegEbp;
  }
  else
  if ((pCtxRec->ctx_RegEsp & 0x3) == 0 &&
      pCtxRec->ctx_RegEsp > (ULONG)pStackPtr &&
      (void*)pCtxRec->ctx_RegEsp < ptib->tib_pstacklimit) {
    pStackPtr = (char*)pCtxRec->ctx_RegEsp;
  }

  for (; pStackPtr < (char*)ptib->tib_pstacklimit; pStackPtr += 4) {
    TimedBeep();
    ul = *(PULONG)pStackPtr;
    if (ul < 0x10000L)
      continue;

    ulSize = 4;
    rc = DosQueryMem((void*)ul, &ulSize, &ulAttr);
    if (rc || ~ulAttr & PAG_COMMIT || ~ulAttr & PAG_EXECUTE)
      continue;

    rc = DosQueryModFromEIP(&hMod, &ulObjNum, CCHMAXPATH,
                            szModName, &ulOffset, ul);
    if (rc || ulOffset == 0xffffffff)
      continue;

    fprintf(hTrap, " %08lX  %08lX   %-08s  %04lX:%08lX ",
            pStackPtr, ul, szModName, ulObjNum + 1, ulOffset);

    /* If the filename can be identified, try to get the symbol's name using
     * embedded debug info or a DBG file; if that fails, try for a .sym file.
     */
    if (DosQueryModuleName(hMod, CCHMAXPATH, szFileName))
      fputc('\n', hTrap);
    else
      if (PrintLineNum(szFileName, ulObjNum, ulOffset, FALSE))
        PrintSymbolFromFile(szFileName, hMod, ulObjNum, ulOffset);

#if 0
   /* Enable to test trap in handler logic */
    if (cTrapCount == 1)
      *(CHAR*)0 = cTrapCount;
#endif
  }

  return;
}

/*****************************************************************************/
/*  The 'Stack Contents' section                                             */
/*****************************************************************************/

void    PrintStackDump(CONTEXTRECORD* pCtxRec)
{
  ULONG     cnt;
  ULONG     flags;
  char *    pStackPtr;

  TimedBeep();

  if (verbosity < XQ_TERSE || !pStackTop)
    return;

  pStackPtr = pStackTop;

  /* Print stack dump.  For terse, print from roughly 64 bytes above ESP to
   * 256 bytes below;  for concise, print from roughly 256 bytes above ESP
   * to the bottom;  for verbose & v-verbose, print the entire valid stack.
  */
  if (verbosity == XQ_TERSE) {
    if (((pCtxRec->ctx_RegEsp & ~0x0f) - 0x40) > (ULONG)pStackPtr)
      pStackPtr = (char*)((pCtxRec->ctx_RegEsp & ~0x0f) - 0x40);
  }
  else
  if (verbosity == XQ_CONCISE) {
    if (((pCtxRec->ctx_RegEsp & ~0x0f) - 0x100) > (ULONG)pStackPtr)
      pStackPtr = (char*)((pCtxRec->ctx_RegEsp & ~0x0f) - 0x100);
  }

  cnt = (char*)ptib->tib_pstacklimit - pStackPtr;

  /* begin header */
  fputs(pszTopLine, hTrap);

  if (verbosity == XQ_TERSE) {
    if (cnt > 0x140)
      cnt = 0x140;
    fprintf(hTrap, " Stack Contents from ESP-%lX to ESP+%lX  (ESP = %08lX)\n",
            (char*)pCtxRec->ctx_RegEsp - pStackPtr,
            (pStackPtr + cnt) - (char*)pCtxRec->ctx_RegEsp,
            pCtxRec->ctx_RegEsp);
  }
  else
  if (verbosity == XQ_CONCISE)
    fprintf(hTrap, " Stack Contents from ESP-%lX to Stack Base  (ESP = %08lX)\n",
            (char*)pCtxRec->ctx_RegEsp - pStackPtr, pCtxRec->ctx_RegEsp);
  else 
    fprintf(hTrap, " Stack Contents from Historic Top to Stack Base  (ESP = %08lX)\n",
            pCtxRec->ctx_RegEsp);

  fputs(pszBotLine, hTrap);
  /* end header */

  flags = XQM_CHARS | XQM_FMT16 |
          ((LOUSHORT(pCtxRec->ctx_SegSs) == FLATDS) ? XQM_DWORDS : XQM_WORDS);

  PrintMemoryHdr(flags);
  PrintMemory(pStackPtr, cnt, flags);

  return;
}

/*****************************************************************************/
/*  The 'Memory addressed by ...' sections                                   */
/*****************************************************************************/

void    PrintRegisterPointers(CONTEXTRECORD* pCtxRec)
{
  ULONG   flags;

  if (verbosity < XQ_TERSE)
    return;

  /* If we can determine whether this is 16- or 32-bit data,
   * show words or dwords;  otherwise, just show bytes.
  */
  if (pCtxRec->ContextFlags & CONTEXT_CONTROL)
    flags = XQM_BYTES | XQM_CHARS | XQM_FMT8 |
            ((LOUSHORT(pCtxRec->ctx_SegDs) == FLATDS) ? XQM_DWORDS : XQM_WORDS);
  else
    flags = XQM_BYTES | XQM_CHARS | XQM_FMT16;

  PrintMemoryAt((char*)pCtxRec->ctx_RegEax, "EAX", flags);
  PrintMemoryAt((char*)pCtxRec->ctx_RegEbx, "EBX", flags);
  PrintMemoryAt((char*)pCtxRec->ctx_RegEcx, "ECX", flags);
  PrintMemoryAt((char*)pCtxRec->ctx_RegEdx, "EDX", flags);
  PrintMemoryAt((char*)pCtxRec->ctx_RegEsi, "ESI", flags);
  PrintMemoryAt((char*)pCtxRec->ctx_RegEdi, "EDI", flags);

  return;
}

/*****************************************************************************/
/* Print memory block if address is valid */

void    PrintMemoryAt(char* pMem, PSZ pszDesc, ULONG flags)
{
  ULONG ulSize;
  ULONG ulAttr;

  TimedBeep();

  if (verbosity == XQ_TERSE)
    ulSize = 64;
  else
  if (verbosity == XQ_VERBOSE)
    ulSize = 512;
  else
  if (verbosity == XQ_VERYVERBOSE)
    ulSize = 1024;
  else
    ulSize = 256;

  if (DosQueryMem(pMem, &ulSize, &ulAttr) ||
      (ulAttr & (PAG_COMMIT | PAG_READ)) != (PAG_COMMIT | PAG_READ))
    return;

  fputs(pszTopLine, hTrap);
  fprintf(hTrap, " Memory addressed by %s (%08lX) for %ld bytes\n",
          pszDesc, pMem, ulSize);
  fputs(pszBotLine, hTrap);

  PrintMemoryHdr(flags);
  PrintMemory(pMem, ulSize, flags);

  return;
}

/*****************************************************************************/

void    PrintMemory(char* pMem, ULONG cbMem, ULONG flags)
{
  ULONG   cbLine = flags & XQM_FMTMASK;
  ULONG   cnt = 0;
  char *  pLast = 0;

  for (; cbMem >= cbLine; cbMem -= cbLine, pMem += cbLine) {
    /* Suppress duplicate lines. */
    if (pLast && !memcmp(pMem, pLast, cbLine)) {
      cnt++;
      pLast = pMem;
      continue;
    }
    /* If there's more than one dup line, print the message;  if
     * there's only one, don't suppress it.  Instead, print it now -
     * the current line will get printed on the next iteration.
    */
    if (cnt > 1)
      fprintf(hTrap, pszDupLine, pLast, cnt);
    if (cnt == 1)
      pMem = pLast;
    else
      pLast = pMem;
    cnt = 0;

    /* Print a full line. */
    PrintMemoryLine(pMem, cbLine, flags);
  }

  /* If the final lines were dups, print the msg now. */
  if (cnt)
    fprintf(hTrap, pszDupLine, pLast, cnt);

  /* If cbMem wasn't a multiple of cbLine, print the remaining bytes. */
  if (cbMem)
    PrintMemoryLine(pMem, cbMem, flags);

  return;
}

/*****************************************************************************/

void    PrintMemoryLine(char* pSrc, ULONG cbSrc, ULONG flags)
{
  ULONG   cbLine = flags & XQM_FMTMASK;
  ULONG   ctr;
  char *  pDst;

  pDst = szBuffer;
  pDst += sprintf(pDst, " %08lX ", pSrc);

  if (flags & (XQM_WORDS | XQM_DWORDS)) {
    pDst = strcpy(pDst, ": ") + 2;
    if (flags & XQM_DWORDS) {
      for (ctr = 0; ctr < cbSrc/4; ctr++)
        pDst += sprintf(pDst, "%08lX ", ((ULONG*)pSrc)[ctr]);

      if (ctr < cbLine/4)
        pDst += sprintf(pDst, "%*s", 9*((cbLine/4)-ctr), "");
    }
    else {
      for (ctr = 0; ctr < cbSrc/2; ctr++)
        pDst += sprintf(pDst, "%04hX ", ((USHORT*)pSrc)[ctr]);

      if (ctr < cbLine/2)
        pDst += sprintf(pDst, "%*s", 5*((cbLine/2)-ctr), "");
    }
  }

  if (flags & XQM_BYTES) {
    pDst = strcpy(pDst, ": ") + 2;
    for (ctr = 0; ctr < cbSrc; ctr++)
      pDst += sprintf(pDst, "%02hX ", pSrc[ctr]);

    if (cbSrc < cbLine)
      pDst += sprintf(pDst, "%*s", 3*(cbLine-cbSrc), "");
  }

  if (flags & XQM_CHARS) {
    pDst = strcpy(pDst, ": ") + 2;
    for (ctr = 0; ctr < cbSrc; ctr++)
      *pDst++ = (isprint(pSrc[ctr]) && pSrc[ctr] >= 0x20) ? pSrc[ctr] : '.';
  }

  strcpy(pDst, "\n");
  fputs(szBuffer, hTrap);

  return;
}

/*****************************************************************************/

void    PrintMemoryHdr(ULONG flags)
{
  ULONG   cbLine = flags & XQM_FMTMASK;
  ULONG   width;
  char *  pDst;

  pDst = szBuffer;
  pDst = strcpy(pDst, " --addr--") + 9;

  if (flags & (XQM_WORDS | XQM_DWORDS)) {
    pDst = strcpy(pDst, "   ") + 3;
    if (flags & XQM_DWORDS) {
      width = (2 * cbLine) + ((cbLine / 4) - 1) - 6;
      pDst = (char*)memset(pDst, '-', width/2) + width/2;
      pDst = strcpy(pDst, "dwords") + 6;
    }
    else {
      width = (2 * cbLine) + ((cbLine / 2) - 1) - 5;
      pDst = (char*)memset(pDst, '-', width/2) + width/2;
      pDst = strcpy(pDst, "words") + 5;
    }
    width -= width/2;
    pDst = (char*)memset(pDst, '-', width) + width;
  }

  if (flags & XQM_BYTES) {
    pDst = strcpy(pDst, "   ") + 3;
    width = (2 * cbLine) + (cbLine - 1) - 5;
    pDst = (char*)memset(pDst, '-', width/2) + width/2;
    pDst = strcpy(pDst, "bytes") + 5;
    width -= width/2;
    pDst = (char*)memset(pDst, '-', width) + width;
  }

  if (flags & XQM_CHARS) {
    pDst = strcpy(pDst, "   ") + 3;
    width = cbLine - 5;
    pDst = (char*)memset(pDst, '-', width/2) + width/2;
    pDst = strcpy(pDst, "chars") + 5;
    width -= width/2;
    pDst = (char*)memset(pDst, '-', width) + width;
  }

  strcpy(pDst, "\n");
  fputs(szBuffer, hTrap);

  return;
}

/*****************************************************************************/
/*  The 'DLLs accessible from this process' section                          */
/*****************************************************************************/

#define XQ_BASE_ADDR   0x04000000
#define XQ_MAX_ADDR    0x1FFFFFFF
#define XQ_CODE_ATTR   (PAG_EXECUTE | PAG_BASE | PAG_SHARED)
#define XQ_PMOD_MAX    ((HMODULE*)(&bigBuf[sizeof(bigBuf)]))

void    PrintDlls(void)
{
  APIRET    rc;
  void*     pvBase;
  ULONG     ulSize;
  ULONG     ulAttr;
  ULONG     ulObjNum;
  ULONG     ulOffset;
  HMODULE   hMod;
  HMODULE * pahMod;
  char *    ptr;

  if (verbosity < XQ_TERSE)
    return;

  /* Scan the low-memory shared arena (i.e. from 64mb to 512mb) */
  memset(bigBuf, 0, sizeof(bigBuf));
  pvBase = (void*)XQ_BASE_ADDR;
  ulSize = XQ_MAX_ADDR - XQ_BASE_ADDR;

  do {
    TimedBeep();
    rc = DosQueryMem(pvBase, &ulSize, &ulAttr);
    if (rc) {
      if (rc == ERROR_INVALID_ADDRESS || rc == ERROR_NO_OBJECT) {
        pvBase = (PCHAR)pvBase + 0x10000;
        ulSize = (PCHAR)XQ_MAX_ADDR - (PCHAR)pvBase;
        continue;
      }
      fprintf(hTrap, " PrintDlls:  DosQueryMem failed - rc= %ld\n", rc);
      return;
    }

    if ((ulAttr & XQ_CODE_ATTR) == XQ_CODE_ATTR) {
      rc = DosQueryModFromEIP(&hMod, &ulObjNum, CCHMAXPATH,
                              szModName, &ulOffset, (ULONG)pvBase);
      if (!rc) {
        for (pahMod = (HMODULE*)bigBuf; pahMod < XQ_PMOD_MAX; pahMod++) {
          if (*pahMod == hMod)
            break;

          if (!*pahMod) {
            *pahMod = hMod;
            break;
          }
        }
        if (pahMod >= XQ_PMOD_MAX)
          break;
      }
    }

    /* round size up to multiple of 64k */
    ulSize += 0x0FFFF;
    ulSize &= 0xFFFF0000;
    pvBase = (PCHAR)pvBase + ulSize;
    ulSize = ((PCHAR)XQ_MAX_ADDR) - (PCHAR)pvBase;

  } while (pvBase < (void*)XQ_MAX_ADDR);

  fputs(pszTopLine, hTrap);
  fputs(" DLLs accessible from this process\n", hTrap);
  fputs(pszBotLine, hTrap);

  for (pahMod = (HMODULE*)bigBuf; pahMod < XQ_PMOD_MAX; pahMod++) {
    TimedBeep();
    if (!*pahMod) {
      break;
    }

    if (DosQueryModuleName(*pahMod, CCHMAXPATH, szFileName))
      strcpy(szFileName, "unknown");

    ptr = strrchr(szFileName, '\\');
    ptr = ptr ? ptr + 1 : szFileName;
    strcpy(szModName, ptr);
    ptr = strchr(szModName, '.');
    if (ptr)
      *ptr = 0;

    fprintf(hTrap, " %-8s    %s\n", szModName, szFileName);
  }

  if (pahMod >= XQ_PMOD_MAX)
    fputs("\n Warning: capacity exceeded.  Additional DLLs may not have been listed.\n",
          hTrap);

  return;
}

/*****************************************************************************/
/*  Utilities:  WalkStack, TimedBeep                                         */
/*****************************************************************************/
/* Walk stack and print function addresses and local variables.
 * Better New WalkStack From John Currier.
 */

void    WalkStack(void* pvStackBottom, void* pvStackTop,
                  ULONG ulEBP, USHORT usSS, ULONG ulEIP, USHORT usCS)
{
  APIRET    rc;
  HMODULE   hMod;
  ULONG     ul32BitAddr;
  ULONG     ulLastEbp;
  ULONG     ulSize;
  ULONG     ulAttr;
  ULONG     ulObjNum;
  ULONG     ulOffset;
  BOOL      isPass1;
  BOOL      is32Bit;
  BOOL      printLocals;

  /* Note: we can't handle stacks bigger than 64K for now... */

  fprintf(hTrap, pszStackHdr, "EBP");

  /* Use passed address 1st time thru */
  isPass1 = TRUE;
  is32Bit = usCS == FLATCS;

  for (;;) {
    TimedBeep();

    ulSize = 12;    /* sufficient to hold ebp, cs:eip */
    if (is32Bit)
      rc = DosQueryMem((void*)(ulEBP), &ulSize, &ulAttr);
    else {
      ul32BitAddr = (ULONG)(usSS & ~7) << 13 | ulEBP;
      rc = DosQueryMem((void*)(ul32BitAddr), &ulSize, &ulAttr);
    }

    if (rc || ~ulAttr & PAG_COMMIT || ulSize < 12) {
      if (is32Bit)
        fprintf(hTrap, " Invalid EBP %08lX\n", ulEBP);
      else
        fprintf(hTrap, " Invalid SS:BP: %04hX:%04lX\n", usSS, ulEBP);
      break;
    }

    /* If pass1, use passed initial values else get from stack */
    if (!isPass1) {
      if (is32Bit) {
        ulEIP = *((PULONG)(ulEBP + 4));
        /* If there's a "return address" of FLATDS following
         * EBP on the stack we have to adjust EBP by 44 bytes to get
         * at the real return address.  This has something to do with
         * calling 32-bit code via a 16-bit interface
         * This offset applies to VAC runtime and might vary for others.
         */
        if (ulEIP == FLATDS) {
          ulEBP += 44;
          ulEIP = *(PULONG)(ulEBP + 4);
        }
      }
      else {
        ulEIP = *((PUSHORT)(ul32BitAddr + 2));
        usCS = *(PUSHORT)(ul32BitAddr + 4);
        /* If CS is now FLATDS, we are returning
         * to 32 bit code from 16-bit code
         * fixme to check ulEIP == 0x150B?
         */
        if (usCS == FLATDS) {
          ulEBP = ul32BitAddr + 20;
          usSS = FLATDS;
          ulEIP = *(PULONG)(ulEBP + 4);
          usCS = FLATCS;
          is32Bit = TRUE;
        }
      }
    }

    if (!is32Bit) {
      /* If the return address points to the stack then it's
       * really just a pointer to the return address (UGH!).
       */
      if (usCS == usSS) {
        ul32BitAddr = (ULONG)(usSS & ~7) << 13 | ulEIP;
        ulEIP = *(PUSHORT)(ul32BitAddr);
        usCS = *(PUSHORT)(ul32BitAddr + 2);
      }

      /* End of the stack so these are both shifted by 2 bytes */
      if (ulEIP == 0 && *(PUSHORT)ulEBP == 0) {
        ul32BitAddr = (ULONG)(usSS & ~7) << 13 | ulEBP;
        ulEIP = *(PUSHORT)(ul32BitAddr + 4);
        usCS = *(PUSHORT)(ul32BitAddr + 6);
      }
    }

    /* For far calls in 16-bit programs have on the stack:
     *   BP:IP:CS
     *   where CS may be thunked
     *
     *     in byte order               swapped
     *    BP        IP   CS          BP   CS   IP
     *   4677      53B5 F7D0        7746 D0F7 B553
     *
     * for near calls 32bit programs have:
     *   EBP:EIP
     * and you'd have something like this (with SP added) (not
     * accurate values)
     *
     *       in byte order           swapped
     *      EBP       EIP         EBP       EIP
     *   4677 2900 53B5 F7D0   0029 7746 D0F7 B553
     *
     * So the basic difference is that 32bit programs have a 32bit
     * EBP and we can attempt to determine whether we have a 32bit
     * EBP by checking to see if its 'selector' is the same as SP.
     * Note that this technique limits us to checking stacks < 64K.
     *
     * Soooo, if IP (which maps into the same USHORT as the swapped
     * stack page in EBP) doesn't point to the stack (i.e. it could
     * be a 16bit IP) then see if CS is valid (as is or thunked).
     *
     * Note that there's the possibility of a 16bit return address
     * that has an offset that's the same as SP so we'll think it's
     * a 32bit return address and won't be able to successfully resolve
     * its details.
     */

    if (!is32Bit) {
      if (ulEIP != usSS) {
        if (DOS16SIZESEG((USHORT)usCS, &ulSize) == NO_ERROR)
          ; /* ulRetAddr = MAKEULONG(ulEIP, usCS);  27 Jul 07 SHL */
        else
        if (DOS16SIZESEG((usCS << 3) | 7, &ulSize) == NO_ERROR) {
          /* usCS = (usCS << 3) | 7; */
          /* ulRetAddr = (ULONG)(USHORT * _Seg16)MAKEULONG(ulEIP, usCS); */
        }
        else {
          is32Bit = TRUE;
          /* fixme to be sure this is right */
          ulEIP = (ULONG)usCS << 16 | ulEIP;
          usCS = FLATCS;    /* fixme? */
        }
      }
      else {
        /* fixme to get adjusted EIP? */
        is32Bit = TRUE;
        usCS = FLATCS;      /* fixme? */
      }
    }

    if (isPass1)
      fputs(" Trap  ->", hTrap);
    else
      fprintf(hTrap, " %08lX", ulEBP);

    if (is32Bit)
      fprintf(hTrap, "  %08lX ", ulEIP);
    else
      fprintf(hTrap, "  %04hX:%04lX", usCS, ulEIP);

    /* Avoid error 87 when ulSize is 0 */
    ulSize = 10;
    if (is32Bit)
      ul32BitAddr = ulEIP;
    else
      ul32BitAddr = (ULONG)(usCS & ~7) << 13 | ulEIP;

    rc = DosQueryMem((void*)ul32BitAddr, &ulSize, &ulAttr);
    if (rc || ~ulAttr & PAG_COMMIT) {
      fprintf(hTrap, "  Invalid address: %08lX\n", ul32BitAddr);
      break;        /* avoid infinite loops */
    }

    printLocals = FALSE;
    rc = DosQueryModFromEIP(&hMod, &ulObjNum, sizeof(szModName),
                            szModName, &ulOffset, (ULONG)ul32BitAddr);
    if (rc || ulObjNum == -1)
      fputs("  *Unknown*\n", hTrap);
    else {
      fprintf(hTrap, "  %-08s  %04lX:%08lX ", szModName, ulObjNum + 1, ulOffset);

      /* If the filename can be identified, try to get the symbol's name using
       * embedded debug info or a DBG file; if that fails, try for a sym file.
       */
      if (DosQueryModuleName(hMod, sizeof(szFileName), szFileName))
        fputc('\n', hTrap);
      else
        if (!PrintLineNum(szFileName, ulObjNum, ulOffset, TRUE))
          printLocals = TRUE;
        else
          PrintSymbolFromFile(szFileName, hMod, ulObjNum, ulOffset);
    }

    /* Double-space the call-stack listing. */
    fputc('\n', hTrap);

    if (is32Bit) {
      /* If EBP points to the FLATDS rather than something that looks
       * like a pointer, we are probably looking at a thunk sequence.
       * For VAC this is 0x44 bytes in size  - 19 Jul 07 SHL
       */
      if (*(PULONG)ulEBP == FLATDS)
        ulEBP += 0x44;
      /* End of call stack */
      if (*(PULONG)ulEBP == 0) {
        break;
      }
    }
    else {
      ul32BitAddr = (ULONG)(usSS & ~7) << 13 | ulEBP;
      ulEBP = *(PUSHORT)ul32BitAddr;

      /* 0x0000 0xFFFF fixme? */

      /* End of call stack */
      if (ulEBP == 0 && *(PUSHORT)(ul32BitAddr + 2) == 0)
        break;
    }

    if (isPass1) {
      isPass1 = FALSE;
      if (is32Bit && printLocals) {
        if (PrintLocalVariables(ulEBP))
          fputc('\n', hTrap);
      }
    }
    else {
      ulLastEbp = ulEBP;

      /* Inserted by Kim Rasmussen 26/06 1996 to allow big stacks */
      if (is32Bit)
        ulEBP = *(PULONG)ulLastEbp;
      else
        ulEBP = MAKEULONG(ulEBP, usSS);

      if (is32Bit && printLocals) {
        if (PrintLocalVariables(ulEBP))
          fputc('\n', hTrap);
      }

      if (ulEBP < ulLastEbp) {
        fputs(" Lost Stack chain - new EBP below previous\n", hTrap);
        break;
      }
    }

    ulSize = 4;
    if (is32Bit)
      rc = DosQueryMem((void*)ulEBP, &ulSize, &ulAttr);
    else {
      ul32BitAddr = (ULONG)(usSS & ~7) << 13 | ulEBP;
      rc = DosQueryMem((void*)ul32BitAddr, &ulSize, &ulAttr);
    }

    if (rc != NO_ERROR || ulSize < 4) {
      if (is32Bit)
        fprintf(hTrap, " Lost Stack chain - invalid EBP %08lX\n", ulEBP);
      else
        fprintf(hTrap, " Lost Stack chain - invalid SS:BP %04hX:%04lX\n", usSS, ulEBP);
      break;
    }

  } /* forever */

  return;
}

/*****************************************************************************/

/* Emit a signature beep sequence at the start, and then a
 * non-threatening low-toned beep every 1.5 seconds thereafter.
 */

void    TimedBeep(void)
{
  static ULONG  ulNextBeep = 0;

  ULONG     now;

  if (!fBeep)
    return;

  DosQuerySysInfo(QSV_MS_COUNT, QSV_MS_COUNT, &now, sizeof(now));
  if (now > ulNextBeep) {
    if (!ulNextBeep) {
      DosBeep(220, 32);
      DosBeep(880, 32);
      DosBeep(440, 32);
    }
    else
      DosBeep(220, 32);

    ulNextBeep = now + 1500;
  }

  return;
}

/*****************************************************************************/

