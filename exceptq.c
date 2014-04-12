/**********************************************************************/
/*                                                                    */
/*  EXCEPTQ                                                           */
/*                                                                    */
/* DLL containing an exception handler for gathering trap information */
/* This DLL dumps all important debugging Data and is accessible      */
/* from both 16 bit and 32 bits programs                              */
/**********************************************************************/
/* Version: 2.2             |   Marc Fiammante (FIAMMANT at LGEPROFS) */
/*                          |   La Gaude FRANCE                       */
/*                          |   Internet: fiammante@vnet.ibm.com      */
/* Version: 5.0             |   John Currier  (JCURRIER at CLTVM1)    */
/*                          |   Internet: currier@vnet.ibm.com        */
/* Version: 6.0             |   Kim Rasmussen (krasmus@ibm.net)       */
/*                          |   Denmark                               */
/* Version: 6.1             |   Anthony Cruise (CRUISE at YKTVMH)     */
/*                          |   Watson Research                       */
/* Version: 6.2             |   John Currier  (JCURRIER at CLTVM1)    */
/*                          |   Internet: currier@vnet.ibm.com        */
/* Version: 6.3             |   Kim Rasmussen (kr@belle.dk)           */
/*                          |   Denmark                               */
/*                          |   Marc Fiammante (FIAMMANT at LGEPROFS) */
/*                          |   La Gaude FRANCE                       */
/*                          |   Internet: fiammante@vnet.ibm.com      */
/* Version: 6.4             |   Kim Rasmussen (kr@belle.dk)           */
/*                          |   Denmark - http://www.belle.dk/kr/     */
/**********************************************************************/
/*                                                                    */
/**********************************************************************/
/* History:                                                           */
/* --------                                                           */
/*                                                                    */
/* created: Marc Fiammante December 1992                              */
/* changed: John Currier   August   1994                              */
/* changed: Kim Rasmussen, May 1995                                   */
/*    Dump of auto-variables added (32-bit only)                      */
/* changed: Anthony Cruise, May 1995                                  */
/*    Do not dump duplicate lines  (32-bit only)                      */
/* fixed  : Marc Fiammante thanks to Bill Siddall                     */
/*    Dump of auto-variables wrong values                             */
/* fixed  : John Currier fix stack thunk on non fatal exceptions      */
/*         fixed DosQueryMem Size test on return                      */
/* fixed  : Marc Fiammante find stack bottom from top to bottom       */
/*         avoid traps on disassemble.                                */
/* changed: Support for VisualAge C added (new debug format)          */
/*                                                                    */
/**********************************************************************/
#define INCL_BASE
#define INCL_DOSEXCEPTIONS
#define INCL_DOSSEMAPHORES   /* Semaphore values */
#include <os2.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "sym.h"
#include "omf.h"

#ifndef DWORD
#define DWORD unsigned long
#endif
#ifndef WORD
#define WORD  unsigned short
#endif
#pragma stack16(512)
#define HF_STDERR 2
UCHAR *ProcessName = "DEBUGGEE.EXE";
FILE   *hTrap;
static BOOL   f32bit = TRUE;
struct debug_buffer
 {
   ULONG   Pid;        /* Debuggee Process ID */
   ULONG   Tid;        /* Debuggee Thread ID */
   LONG    Cmd;        /* Command or Notification */
   LONG    Value;      /* Generic Data Value */
   ULONG   Addr;       /* Debuggee Address */
   ULONG   Buffer;     /* Debugger Buffer Address */
   ULONG   Len;        /* Length of Range */
   ULONG   Index;      /* Generic Identifier Index */
   ULONG   MTE;        /* Module Handle */
   ULONG   EAX;        /* Register Set */
   ULONG   ECX;
   ULONG   EDX;
   ULONG   EBX;
   ULONG   ESP;
   ULONG   EBP;
   ULONG   ESI;
   ULONG   EDI;
   ULONG   EFlags;
   ULONG   EIP;
   ULONG   CSLim;      /* Byte Granular Limits */
   ULONG   CSBase;     /* Byte Granular Base */
   UCHAR   CSAcc;      /* Access Bytes */
   UCHAR   CSAtr;      /* Attribute Bytes */
   USHORT  CS;
   ULONG   DSLim;
   ULONG   DSBase;
   UCHAR   DSAcc;
   UCHAR   DSAtr;
   USHORT  DS;
   ULONG   ESLim;
   ULONG   ESBase;
   UCHAR   ESAcc;
   UCHAR   ESAtr;
   USHORT  ES;
   ULONG   FSLim;
   ULONG   FSBase;
   UCHAR   FSAcc;
   UCHAR   FSAtr;
   USHORT  FS;
   ULONG   GSLim;
   ULONG   GSBase;
   UCHAR   GSAcc;
   UCHAR   GSAtr;
   USHORT  GS;
   ULONG   SSLim;
   ULONG   SSBase;
   UCHAR   SSAcc;
   UCHAR   SSAtr;
   USHORT  SS;
} DbgBuf;
/*-------------------------------------*/
APIRET APIENTRY DOSQUERYMODFROMEIP( HMODULE *phMod,
                                    ULONG *pObjNum,
                                    ULONG BuffLen,
                                    PCHAR pBuff,
                                    ULONG *pOffset,
                                    PVOID Address );
APIRET APIENTRY DosQueryModFromEIP( HMODULE *phMod,
                                    ULONG *pObjNum,
                                    ULONG BuffLen,
                                    PCHAR pBuff,
                                    ULONG *pOffset,
                                    PVOID Address );

/*-------------------------------------*/
#define DBG_O_OBJMTE       0x10000000L
#define DBG_C_NumToAddr            13
#define DBG_C_AddrToObject         28
#define DBG_C_Connect              21
#define DBG_L_386                   1
RESULTCODES ReturnCodes;
UCHAR   LoadError[40]; /*DosExecPGM buffer */
USHORT Passes;
UCHAR   Translate[17];
UCHAR   OldStuff[16];
#ifdef USE_DOSDEBUG
void    GetObjects(struct debug_buffer * pDbgBuf,HMODULE hMte,PSZ pName);
#endif
VOID    ListModules(VOID);
void    CheckMem(PVOID Ptr,PSZ MemoryName);
/* Better New WalkStack From John Currier */
static void WalkStack(PUSHORT StackBottom,PUSHORT StackTop,PUSHORT Ebp,PUSHORT ExceptionAddress);
int    Read16CodeView(int fh,int TrapSeg,int TrapOff,CHAR * FileName);
int    Read32PmDebug(int fh,int TrapSeg,int TrapOff,CHAR * FileName);
APIRET GetLineNum(CHAR * FileName, ULONG Object,ULONG TrapOffset);
void GetSymbol(CHAR * SymFileName, ULONG Object,ULONG TrapOffset);
void print_vars(ULONG stackofs);

ULONG func_ofs;
ULONG pubfunc_ofs;
char  func_name[128];
ULONG var_ofs = 0;

struct {
   BYTE name[128];
   ULONG stack_offset;
   USHORT type_idx;
} autovar_def[100];

HMODULE hMod;
ULONG   ObjNum;
ULONG   Offset;
/*-------------------------------------*/
CHAR    Buffer[CCHMAXPATH];

typedef ULONG     * _Seg16 PULONG16;
APIRET16 APIENTRY16 DOS16SIZESEG( USHORT Seg , PULONG16 Size);
typedef  APIRET16  (APIENTRY16  _PFN16)();
ULONG  APIENTRY DosSelToFlat(ULONG);
/*-------------------------------------*/
/*- DosQProcStatus interface ----------*/
APIRET16 APIENTRY16 DOSQPROCSTATUS(  ULONG * _Seg16 pBuf, USHORT cbBuf);
#define CONVERT(fp,QSsel) MAKEP((QSsel),OFFSETOF(fp))
#pragma pack(1)
/*  Global Data Section */
typedef struct qsGrec_s {
    ULONG     cThrds;  /* number of threads in use */
    ULONG     Reserved1;
    ULONG     Reserved2;
}qsGrec_t;
/* Thread Record structure *   Holds all per thread information. */
typedef struct qsTrec_s {
    ULONG     RecType;    /* Record Type */
                          /* Thread rectype = 100 */
    USHORT    tid;        /* thread ID */
    USHORT    slot;       /* "unique" thread slot number */
    ULONG     sleepid;    /* sleep id thread is sleeping on */
    ULONG     priority;   /* thread priority */
    ULONG     systime;    /* thread system time */
    ULONG     usertime;   /* thread user time */
    UCHAR     state;      /* thread state */
    UCHAR     PADCHAR;
    USHORT    PADSHORT;
} qsTrec_t;
/* Process and Thread Data Section */
typedef struct qsPrec_s {
    ULONG           RecType;    /* type of record being processed */
                          /* process rectype = 1       */
    qsTrec_t *      pThrdRec;  /* ptr to 1st thread rec for this prc*/
    USHORT          pid;       /* process ID */
    USHORT          ppid;      /* parent process ID */
    ULONG           type;      /* process type */
    ULONG           stat;      /* process status */
    ULONG           sgid;      /* process screen group */
    USHORT          hMte;      /* program module handle for process */
    USHORT          cTCB;      /* # of TCBs in use in process */
    ULONG           Reserved1;
    void   *        Reserved2;
    USHORT          c16Sem;     /*# of 16 bit system sems in use by proc*/
    USHORT          cLib;       /* number of runtime linked libraries */
    USHORT          cShrMem;    /* number of shared memory handles */
    USHORT          Reserved3;
    USHORT *        p16SemRec;   /*ptr to head of 16 bit sem inf for proc*/
    USHORT *        pLibRec;     /*ptr to list of runtime lib in use by */
                                  /*process*/
    USHORT *        pShrMemRec;  /*ptr to list of shared mem handles in */
                                  /*use by process*/
    USHORT *        Reserved4;
} qsPrec_t;
/* 16 Bit System Semaphore Section */
typedef struct qsS16Headrec_s {
    ULONG     RecType;   /* semaphore rectype = 3 */
    ULONG     Reserved1;  /* overlays NextRec of 1st qsS16rec_t */
    ULONG     Reserved2;
    ULONG     S16TblOff;  /* index of first semaphore,SEE PSTAT OUTPUT*/
                          /* System Semaphore Information Section     */
} qsS16Headrec_t;
/*  16 bit System Semaphore Header Record Structure */
typedef struct qsS16rec_s {
    ULONG      NextRec;          /* offset to next record in buffer */
    UINT       s_SysSemOwner ;   /* thread owning this semaphore    */
    UCHAR      s_SysSemFlag ;    /* system semaphore flag bit field */
    UCHAR      s_SysSemRefCnt ;  /* number of references to this    */
                                 /*  system semaphore               */
    UCHAR      s_SysSemProcCnt ; /*number of requests by sem owner  */
    UCHAR      Reserved1;
    ULONG      Reserved2;
    UINT       Reserved3;
    CHAR       SemName[1];       /* start of semaphore name string */
} qsS16rec_t;
/*  Executable Module Section */
typedef struct qsLrec_s {
    void        * pNextRec;    /* pointer to next record in buffer */
    USHORT        hmte;         /* handle for this mte */
    USHORT        Reserved1;    /* Reserved */
    ULONG         ctImpMod;     /* # of imported modules in table */
    ULONG         Reserved2;    /* Reserved */
/*  qsLObjrec_t * Reserved3;       Reserved */
    ULONG       * Reserved3;    /* Reserved */
    UCHAR       * pName;        /* ptr to name string following stru*/
} qsLrec_t;
/*  Shared Memory Segment Section */
typedef struct qsMrec_s {
    struct qsMrec_s *MemNextRec;    /* offset to next record in buffer */
    USHORT    hmem;          /* handle for shared memory */
    USHORT    sel;           /* shared memory selector */
    USHORT    refcnt;        /* reference count */
    CHAR      Memname[1];    /* start of shared memory name string */
} qsMrec_t;
/*  Pointer Record Section */
typedef struct qsPtrRec_s {
    qsGrec_t       *  pGlobalRec;        /* ptr to the global data section */
    qsPrec_t       *  pProcRec;          /* ptr to process record section  */
    qsS16Headrec_t *  p16SemRec;         /* ptr to 16 bit sem section      */
    void           *  Reserved;          /* a reserved area                */
    qsMrec_t       *  pShrMemRec;        /* ptr to shared mem section      */
    qsLrec_t       *  pLibRec;           /*ptr to exe module record section*/
} qsPtrRec_t;
/*-------------------------*/
ULONG * pBuf,*pTemp;
USHORT  Selector;
qsPtrRec_t * pRec;
qsLrec_t   * pLib;
qsMrec_t   * pShrMemRec;        /* ptr to shared mem section      */
qsPrec_t   * pProc;
qsTrec_t   * pThread;
ULONG      ListedThreads=0;
APIRET16 APIENTRY16 DOS16ALLOCSEG(
        USHORT          cbSize,          /* number of bytes requested                   */
        USHORT  * _Seg16 pSel,           /* sector allocated (returned)                 */
        USHORT fsAlloc);                 /* sharing attributes of the allocated segment */
typedef struct
  {
    short int      ilen;     /* Instruction length */
    long           rref;     /* Value of any IP relative storage reference */
    unsigned short sel;      /* Selector of any CS:eIP storage reference.   */
    long           poff;     /* eIP value of any CS:eIP storage reference. */
    char           longoper; /* YES/NO value. Is instr in 32 bit operand mode? **/
    char           longaddr; /* YES/NO value. Is instr in 32 bit address mode? **/
    char           buf[40];  /* String holding disassembled instruction **/
  } * _Seg16 RETURN_FROM_DISASM;
RETURN_FROM_DISASM CDECL16 DISASM( CHAR * _Seg16 Source, USHORT IPvalue,USHORT segsize );
RETURN_FROM_DISASM AsmLine;
char *SourceBuffer=0;
static USHORT BigSeg;
static ULONG  Version[2];

BYTE *type_name[] = {
   "8 bit signed                     ",
   "16 bit signed                    ",
   "32 bit signed                    ",
   "Unknown (0x83)                   ",
   "8 bit unsigned                   ",
   "16 bit unsigned                  ",
   "32 bit unsigned                  ",
   "Unknown (0x87)                   ",
   "32 bit real                      ",
   "64 bit real                      ",
   "80 bit real                      ",
   "Unknown (0x8B)                   ",
   "64 bit complex                   ",
   "128 bit complex                  ",
   "160 bit complex                  ",
   "Unknown (0x8F)                   ",
   "8 bit boolean                    ",
   "16 bit boolean                   ",
   "32 bit boolean                   ",
   "Unknown (0x93)                   ",
   "8 bit character                  ",
   "16 bit characters                ",
   "32 bit characters                ",
   "void                             ",
   "15 bit unsigned                  ",
   "24 bit unsigned                  ",
   "31 bit unsigned                  ",
   "Unknown (0x9B)                   ",
   "Unknown (0x9C)                   ",
   "Unknown (0x9D)                   ",
   "Unknown (0x9E)                   ",
   "Unknown (0x9F)                   ",
   "near pointer to 8 bit signed     ",
   "near pointer to 16 bit signed    ",
   "near pointer to 32 bit signed    ",
   "Unknown (0xA3)                   ",
   "near pointer to 8 bit unsigned   ",
   "near pointer to 16 bit unsigned  ",
   "near pointer to 32 bit unsigned  ",
   "Unknown (0xA7)                   ",
   "near pointer to 32 bit real      ",
   "near pointer to 64 bit real      ",
   "near pointer to 80 bit real      ",
   "Unknown (0xAB)                   ",
   "near pointer to 64 bit complex   ",
   "near pointer to 128 bit complex  ",
   "near pointer to 160 bit complex  ",
   "Unknown (0xAF)                   ",
   "near pointer to 8 bit boolean    ",
   "near pointer to 16 bit boolean   ",
   "near pointer to 32 bit boolean   ",
   "Unknown (0xB3)                   ",
   "near pointer to 8 bit character  ",
   "near pointer to 16 bit characters",
   "near pointer to 32 bit characters",
   "near pointer to void             ",
   "near pointer to 15 bit unsigned  ",
   "near pointer to 24 bit unsigned  ",
   "near pointer to 31 bit unsigned  ",
   "Unknown (0xBB)                   ",
   "Unknown (0xBC)                   ",
   "Unknown (0xBD)                   ",
   "Unknown (0xBE)                   ",
   "Unknown (0xBF)                   ",
   "far pointer to 8 bit signed      ",
   "far pointer to 16 bit signed     ",
   "far pointer to 32 bit signed     ",
   "Unknown (0xC3)                   ",
   "far pointer to 8 bit unsigned    ",
   "far pointer to 16 bit unsigned   ",
   "far pointer to 32 bit unsigned   ",
   "Unknown (0xC7)                   ",
   "far pointer to 32 bit real       ",
   "far pointer to 64 bit real       ",
   "far pointer to 80 bit real       ",
   "Unknown (0xCB)                   ",
   "far pointer to 64 bit complex    ",
   "far pointer to 128 bit complex   ",
   "far pointer to 160 bit complex   ",
   "Unknown (0xCF)                   ",
   "far pointer to 8 bit boolean     ",
   "far pointer to 16 bit boolean    ",
   "far pointer to 32 bit boolean    ",
   "Unknown (0xD3)                   ",
   "far pointer to 8 bit character   ",
   "far pointer to 16 bit characters ",
   "far pointer to 32 bit characters ",
   "far pointer to void              ",
   "far pointer to 15 bit unsigned   ",
   "far pointer to 24 bit unsigned   ",
   "far pointer to 31 bit unsigned   ",
};

/*--                                 --*/
/*-------------------------------------*/


typedef  _PFN16 * _Seg16 PFN16;
/*--                                 --*/
static BOOL InForceExit =FALSE;
/*-------------------------------------*/
ULONG APIENTRY HandleFatalException (PEXCEPTIONREPORTRECORD       pERepRec,
                          PEXCEPTIONREGISTRATIONRECORD pERegRec,
                          PCONTEXTRECORD               pCtxRec,
                          PVOID                        p);
// Thanks to John Currier :
// Do not call 16 bit code in myHandler function to prevent call
// to __EDCThunkProlog and problems is guard page exception handling
// Also reduce the stack size to 1K for true 16 bit calls.
// 16 bit calls thunk will now only occur on fatal exceptions
#pragma stack16(1024)
ULONG APIENTRY myHandler (PEXCEPTIONREPORTRECORD       pERepRec,
                          PEXCEPTIONREGISTRATIONRECORD pERegRec,
                          PCONTEXTRECORD               pCtxRec,
                          PVOID                        p)
{
   ULONG rc = XCPT_CONTINUE_SEARCH;

   if ((pERepRec->ExceptionNum & XCPT_SEVERITY_CODE) == XCPT_FATAL_EXCEPTION)
   {
      if (pERepRec->ExceptionNum != XCPT_PROCESS_TERMINATE &&
          pERepRec->ExceptionNum != XCPT_UNWIND &&
          pERepRec->ExceptionNum != XCPT_SIGNAL &&
          pERepRec->ExceptionNum != XCPT_BREAKPOINT &&
          pERepRec->ExceptionNum != XCPT_SINGLE_STEP &&
          pERepRec->ExceptionNum != XCPT_ASYNC_PROCESS_TERMINATE)
      {
         // If any of the above conditionals fail then we have to handle
         //    the fatal trap.
         rc = HandleFatalException(pERepRec, pERegRec, pCtxRec, p);
      }
   }

   return rc;
}

ULONG APIENTRY HandleFatalException (PEXCEPTIONREPORTRECORD       pERepRec,
                          PEXCEPTIONREGISTRATIONRECORD pERegRec,
                          PCONTEXTRECORD               pCtxRec,
                          PVOID                        p)
{
  PCHAR   SegPtr;
  PUSHORT StackPtr;
  PUSHORT ValidStackBottom;
  PUCHAR  TestStackBottom;
  PUCHAR  cStackPtr;
  ULONG Size,Flags,Attr,CSSize;
  APIRET rc;
  APIRET semrc;
  APIRET16 rc16;
  PTIB   ptib;
  PPIB   ppib;
  USHORT Count;
  ULONG  Nest;
  UCHAR  TrapFile[20];
  struct debug_buffer DbgBuf;
  static CHAR Name[CCHMAXPATH];
  /* Do not recurse into Trapper (John Currier) */
   static BOOL fAlreadyTrapped = FALSE;

  if (InForceExit) {
      return (XCPT_CONTINUE_SEARCH);
  } /* endif */
  if ((pERepRec->ExceptionNum&XCPT_SEVERITY_CODE)==XCPT_FATAL_EXCEPTION)
  {
    if ((pERepRec->ExceptionNum!=XCPT_PROCESS_TERMINATE)&&
        (pERepRec->ExceptionNum!=XCPT_UNWIND)&&
        (pERepRec->ExceptionNum!=XCPT_SIGNAL)&&
        (pERepRec->ExceptionNum!=XCPT_ASYNC_PROCESS_TERMINATE)) {
        DosEnterMustComplete(&Nest);
        rc=DosGetInfoBlocks(&ptib,&ppib);
        if (rc==NO_ERROR) {
           sprintf(TrapFile,"%d%d.TRP",
                   ppib->pib_ulpid,ptib->tib_ptib2->tib2_ultid);
        } else {
           sprintf(TrapFile,"TRAP.TRP");
        }
        printf("Creating %s\n",TrapFile);
        hTrap=fopen(TrapFile,"a");
        if (hTrap==NULL) {
           printf("hTrap NULL\n");
           hTrap=stdout;
        }
        rc=DosError(FERR_DISABLEEXCEPTION | FERR_DISABLEHARDERR );
        setbuf( hTrap, NULL);
        fprintf(hTrap,"--------------------------\n");
        fprintf(hTrap,"Exception %8.8lX Occurred\n",pERepRec->ExceptionNum);
        fprintf(hTrap," at %s ",_strtime(Buffer));
        fprintf(hTrap," %s\n",_strdate(Buffer));
        if ( pERepRec->ExceptionNum     ==         XCPT_ACCESS_VIOLATION)
        {
           switch (pERepRec->ExceptionInfo[0]) {
                case XCPT_READ_ACCESS:
                case XCPT_WRITE_ACCESS:
                   fprintf(hTrap,"Invalid linear address %8.8lX\n",pERepRec->ExceptionInfo[1]);
                   break;
                case XCPT_SPACE_ACCESS:
                  /* Thanks to John Currier              */
                  /* It looks like this is off by one... */
                  fprintf(hTrap,"Invalid Selector: %8.8p",
                                 pERepRec->ExceptionInfo[1] ?
                                 pERepRec->ExceptionInfo[1] + 1 : 0);
                   break;
                case XCPT_LIMIT_ACCESS:
                   fprintf(hTrap,"Limit access fault\n");
                   break;
                case XCPT_UNKNOWN_ACCESS:
                   fprintf(hTrap,"Unknown access fault\n");
                   break;
              break;
           default:
                   fprintf(hTrap,"Other Unknown access fault\n");
           } /* endswitch */
        } /* endif */
       /* John Currier's recursion prevention */
         fprintf(hTrap,"\n\n");

         if (fAlreadyTrapped)
         {
            fprintf(hTrap, "Exception Handler Trapped...aborting evaluation!\n");
            if (hTrap != stderr)
               fclose(hTrap);
            DosExitMustComplete(&Nest);
            DosUnsetExceptionHandler(pERegRec);
            return (XCPT_CONTINUE_SEARCH);
         }

         fAlreadyTrapped = TRUE;
       /* end  John Currier's recursion prevention */
        rc = DosQuerySysInfo(QSV_VERSION_MAJOR,QSV_VERSION_MINOR,
                             Version,sizeof(Version));
        if ((rc==0)&&
            (Version[0]>=20) &&
            (Version[1]>=10) ) {
            /* version must be over 2.1 for DOSQUERYMODFROMEIP */
            fprintf(hTrap,"OS/2 Version %d.%d\n",Version[0]/10,Version[1]);
            rc=DOSQUERYMODFROMEIP( &hMod, &ObjNum, CCHMAXPATH,
                                Name, &Offset, pERepRec->ExceptionAddress);
            if (rc==0) {
              fprintf(hTrap,"Failing code module internal name : %s\n",Name);
              rc=DosQueryModuleName(hMod,CCHMAXPATH, Name);
              fprintf(hTrap,"Failing code module file name : %s\n",Name);
              fprintf(hTrap,"Failing code Object # %d at Offset %x \n",ObjNum+1,Offset);
              if (strlen(Name)>3) {
                 fprintf(hTrap,"      File     Line#  Public Symbol\n");
                 fprintf(hTrap,"  ÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄ-  ÄÄÄÄÄÄÄÄÄÄÄÄ-\n");
                 rc =GetLineNum(Name,ObjNum,Offset);

                 if (rc == 0)
                    print_vars(pCtxRec->ctx_RegEbp);

                 /* if no codeview try with symbol files */
                 if (rc!=0) {
                    strcpy(Name+strlen(Name)-3,"SYM"); /* Get Sym File name */
                    GetSymbol(Name,ObjNum,Offset);
                 } /* endif */
              } /* endif */
              fprintf(hTrap,"\n");
            } else {
               fprintf(hTrap,"Invalid execution address\n");
            } /* endif */
        } /* endif */
        fprintf(hTrap,"ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿\n");
        if ( (pCtxRec->ContextFlags) & CONTEXT_SEGMENTS ) {
             fprintf(hTrap,"³ GS  : %4.4lX     ",pCtxRec->ctx_SegGs);
             fprintf(hTrap,"FS  : %4.4lX     ",pCtxRec->ctx_SegFs);
             fprintf(hTrap,"ES  : %4.4lX     ",pCtxRec->ctx_SegEs);
             fprintf(hTrap,"DS  : %4.4lX     ³\n",pCtxRec->ctx_SegDs);
        } /* endif */
        if ( (pCtxRec->ContextFlags) & CONTEXT_INTEGER  ) {
             fprintf(hTrap,"³ EDI : %8.8lX ",pCtxRec->ctx_RegEdi  );
             fprintf(hTrap,"ESI : %8.8lX ",pCtxRec->ctx_RegEsi  );
             fprintf(hTrap,"EAX : %8.8lX ",pCtxRec->ctx_RegEax  );
             fprintf(hTrap,"EBX : %8.8lX ³\n",pCtxRec->ctx_RegEbx  );
             fprintf(hTrap,"³ ECX : %8.8lX ",pCtxRec->ctx_RegEcx  );
             fprintf(hTrap,"EDX : %8.8lX                               ³\n",pCtxRec->ctx_RegEdx  );
        } /* endif */
        if ( (pCtxRec->ContextFlags) & CONTEXT_CONTROL  ) {
             void * _Seg16 Ptr16;
             fprintf(hTrap,"³ EBP : %8.8lX ",pCtxRec->ctx_RegEbp  );
             fprintf(hTrap,"EIP : %8.8lX ",pCtxRec->ctx_RegEip  );
             fprintf(hTrap,"EFLG: %8.8lX ",pCtxRec->ctx_EFlags  );
             fprintf(hTrap,"ESP : %8.8lX ³\n",pCtxRec->ctx_RegEsp  );
             fprintf(hTrap,"³ CS  : %4.4lX     ",pCtxRec->ctx_SegCs   );
             fprintf(hTrap,"SS  : %4.4lX                                   ³",pCtxRec->ctx_SegSs   );
             SegPtr =MAKEP((SHORT)pCtxRec->ctx_SegCs,0);
             rc16 =DOS16SIZESEG( (USHORT)pCtxRec->ctx_SegCs , &CSSize);
             if (rc16==NO_ERROR) {
                fprintf(hTrap,"\n³ CSLIM: %8.8lX ",CSSize);
             } else {
                CSSize=0;
             } /* endif */
             rc16 =DOS16SIZESEG( (USHORT)pCtxRec->ctx_SegSs , &Size);
             if (rc16==NO_ERROR) {
                fprintf(hTrap,"SSLIM: %8.8lX                             ³",Size);
             } /* endif */
             fprintf(hTrap,"\nÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ\n");
             BigSeg=((pCtxRec->ctx_RegEip)>0x00010000);
             if (BigSeg) {
                 /* Avoid traps in 16:16 Disasm DLL */
                 if (DosAllocMem((PPVOID)&SourceBuffer,0x100,fALLOC)==0) {
                    Size=0x100;
                    rc=DosQueryMem((PVOID)pCtxRec->ctx_RegEip,&Size,&Attr);
                    if (Attr&(PAG_READ|PAG_EXECUTE)) {
                       memcpy(SourceBuffer,(PVOID)pCtxRec->ctx_RegEip,Size);
                       AsmLine= DISASM( (PVOID)SourceBuffer,
                                  (USHORT)pCtxRec->ctx_RegEip, BigSeg );
                       fprintf(hTrap,"\n Failing instruction at CS:EIP : %4.4X:%8.8X is  %s\n\n",
                         pCtxRec->ctx_SegCs,
                         pCtxRec->ctx_RegEip,AsmLine->buf);
                    } /* endif */
                 }
                 fprintf(hTrap,"\nÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿\n");
                 fprintf(hTrap,  "³ Register content analysis          ³\n");
                 fprintf(hTrap,  "ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´\n");
                 CheckMem( (PVOID)pCtxRec->ctx_RegEax,"EAX");
                 CheckMem( (PVOID)pCtxRec->ctx_RegEbx,"EBX");
                 CheckMem( (PVOID)pCtxRec->ctx_RegEcx,"ECX");
                 CheckMem( (PVOID)pCtxRec->ctx_RegEdx,"EDX");
                 CheckMem( (PVOID)pCtxRec->ctx_RegEdi,"EDI");
                 CheckMem( (PVOID)pCtxRec->ctx_RegEsi,"ESI");
                 fprintf(hTrap,"ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ\n");
             } else {
                 if (CSSize>pCtxRec->ctx_RegEip) {
                    AsmLine= DISASM(MAKE16P(pCtxRec->ctx_SegCs,
                                            pCtxRec->ctx_RegEip),
                                    (USHORT)pCtxRec->ctx_RegEip, BigSeg );
                    fprintf(hTrap,"\n Failing instruction at CS:IP : %4.4X:%4.4X is   %s\n\n",
                           pCtxRec->ctx_SegCs,
                           pCtxRec->ctx_RegEip,AsmLine->buf);
                 } else {
                     fprintf(hTrap,"Invalid execution address\n");
                 } /* endif */
                 fprintf(hTrap,"\nÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿\n");
                 fprintf(hTrap,  "³ Source Destination registers pair analysis ³\n");
                 fprintf(hTrap,  "ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´\n");
                 rc16 =DOS16SIZESEG( (USHORT)pCtxRec->ctx_SegDs , &Size);
                 if (rc16==NO_ERROR) {
                    if ((USHORT)Size<(USHORT)pCtxRec->ctx_RegEsi) {
                       fprintf(hTrap,"³ DS:SI points outside Data Segment          ³\n");
                    } else {
                       fprintf(hTrap,"³ DS:SI is a valid source                    ³\n");
                    } /* endif */
                 } else {
                       fprintf(hTrap,"³ DS (Data Segment) Is Invalid               ³\n");
                 } /* endif */
                 rc16 =DOS16SIZESEG( (USHORT)pCtxRec->ctx_SegEs , &Size);
                 if (rc16==NO_ERROR) {
                    if ((USHORT)Size<(USHORT)pCtxRec->ctx_RegEdi) {
                       fprintf(hTrap,"³ ES:DI points outside Extra Segment         ³\n");
                    } else {
                       fprintf(hTrap,"³ ES:DI is a valid destination               ³\n");
                    } /* endif */
                 } else {
                    fprintf(hTrap,"³ ES (Extra Segment) Is Invalid              ³\n");
                 } /* endif */
                 fprintf(hTrap,"ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ\n");
             } /* endif */
             rc=DosGetInfoBlocks(&ptib,&ppib);
             if (rc==NO_ERROR) {
                static CHAR Format[10];
                fprintf(hTrap,"\nThread slot %lu , Id %lu , priority %p\n",
                        ptib->tib_ordinal,
                        ptib->tib_ptib2->tib2_ultid ,
                        ptib->tib_ptib2->tib2_ulpri );
                Ptr16=ptib->tib_pstack;
                sprintf(Format,"%8.8lX",Ptr16);
                fprintf(hTrap,"Stack Bottom : %8.8lX (%4.4s:%4.4s) ;", ptib->tib_pstack ,Format,Format+4);
                Ptr16=ptib->tib_pstacklimit;
                sprintf(Format,"%8.8lX",Ptr16);
                fprintf(hTrap,"Stack Top    : %8.8lX (%4.4s:%4.4s) \n",ptib->tib_pstacklimit,Format,Format+4);
                fprintf(hTrap,"Process Id : %lu ", ppib->pib_ulpid);
                rc=DosQueryModuleName(ppib->pib_hmte,CCHMAXPATH, Name);
                if (rc==NO_ERROR) {
                   fprintf(hTrap,".EXE name : %s\n",Name);
                } else {
                   fprintf(hTrap,".EXE name : ??????\n");
                } /* endif */
               /* Better New WalkStack From John Currier */
               WalkStack((PUSHORT)ptib->tib_pstack,
                         (PUSHORT)ptib->tib_pstacklimit,
                         (PUSHORT)pCtxRec->ctx_RegEbp,
                         (PUSHORT)pERepRec->ExceptionAddress);
                ListModules();
                Count=0;

                fprintf(hTrap,"\n/*----- Stack Bottom ---*/\n");
                /* round to start of page to check first stack valid page  */
               /* Thanks to John Currier for pointing me the guard page problem */
                TestStackBottom =((PUCHAR)ptib->tib_pstacklimit)+0x1000;
                Attr=0;
                do {
                   Size=0x1000;
                   TestStackBottom -=Size; /* One more page for next test */
                   /*if (Attr&PAG_BASE) break;*/
                   rc=DosQueryMem(TestStackBottom-Size,&Size,&Attr);
                } while (
                   ( (rc==0) &&
                     (Attr&PAG_COMMIT) &&
                     (Attr&PAG_READ)
                   ) &&
                   (TestStackBottom >(PUCHAR)ptib->tib_pstack)
                );
                ValidStackBottom=(PUSHORT)TestStackBottom;
                OldStuff[0] =~(*TestStackBottom); /* Make sure first line is printed*/

                if (ValidStackBottom <(PUSHORT)ptib->tib_pstacklimit)

                {
                   fprintf(hTrap,"\n/*----- Accessible Stack Bottom at %p ---*/\n",ValidStackBottom);
                   for (StackPtr=ValidStackBottom;
                        StackPtr<(PUSHORT)ptib->tib_pstacklimit;
                        StackPtr++) {
                        if (Count==0) {
                           if (memcmp(OldStuff,StackPtr,16)){
                               memcpy(OldStuff,StackPtr,16);
                               Passes = 0;
                           } else {
                               if (Passes == 0) {
                                   Passes = 1;
                                   fprintf(hTrap,"  %s\n %8.8X :",Translate,StackPtr);
                                   fprintf(hTrap,"  lines not printed same as above");
                                   strcpy(Translate,"\n");
                               }
                               StackPtr+= 7;
                               continue;
                           }
                        }
                        if (Count==0) {
                           fprintf(hTrap,"  %s\n %8.8X :",Translate,StackPtr);
                           Translate[0]=0x00;
                        } /* endif */
                       /* Change Formatting way (John Currier)*/
                       fprintf(hTrap,"%4.4hX ",*StackPtr >> 8 | *StackPtr << 8);
                        cStackPtr=(PUCHAR)StackPtr;
                        if ((isprint(*cStackPtr)) &&
                            (*cStackPtr>=0x20)  ) {
                           Translate[2*Count]=*cStackPtr;
                        } else {
                           Translate[2*Count]='.';
                        } /* endif */
                        cStackPtr++;
                        if ((isprint(*cStackPtr) )&&
                            ( *cStackPtr >=0x20 )  ) {
                           Translate[2*Count+1]=*cStackPtr;
                        } else {
                           Translate[2*Count+1]='.';
                        } /* endif */
                        Count++;
                        Translate[2*Count]=0x00;
                        if (Count==8) {
                            Count=0;
                        } /* endif */
                   } /* endfor */
                } /* endif */
                fprintf(hTrap,"%s\n/*----- Stack Top -----*/\n",Translate);

             } /* endif */
        } /* endif */
        if (hTrap!=stdout) {
           fclose(hTrap);
        }
        DosExitMustComplete(&Nest);
        rc=DosUnsetExceptionHandler(pERegRec);
     } /* endif */
  } else {
     /* printf("Other non fatal exception %8.8lx ",pERepRec->ExceptionNum); */
     /* printf("At address                %8.8lx\n",pERepRec->ExceptionAddress); */
  } /* endif */
  return (XCPT_CONTINUE_SEARCH);

}
APIRET16 APIENTRY16 SETEXCEPT(PEXCEPTIONREGISTRATIONRECORD _Seg16 pxcpthand)
 {
   APIRET rc;

   rc=DosError(FERR_DISABLEEXCEPTION | FERR_DISABLEHARDERR );
   printf("Set error rc %ld\n",rc);
   pxcpthand->prev_structure=0;
   pxcpthand->ExceptionHandler=&myHandler;
   rc=DosSetExceptionHandler(pxcpthand);
   printf("Set except rc %ld\n",rc);
}
APIRET16 APIENTRY16 UNSETEXCEPT(PEXCEPTIONREGISTRATIONRECORD _Seg16 pxcpthand)
 {
   APIRET rc;
   rc=DosUnsetExceptionHandler(pxcpthand);
   printf("Unset except rc %ld\n",rc);
}
VOID ListModules() {
  APIRET   rc;
  APIRET16 rc16;
#ifdef USE_DOSDEBUG
  /**----------------------------------***/
  rc16=DOS16ALLOCSEG( 0xFFFF , &Selector , 0);
  if (rc16==0) {
     pBuf=MAKEP(Selector,0);
     rc16=DOSQPROCSTATUS(pBuf, 0xFFFF );
     if (rc16==0) {
        rc = DosExecPgm(LoadError,          /* Object name buffer */
                        sizeof(LoadError),  /* Length of object name buffer */
                        EXEC_TRACE,         /* Asynchronous/Trace flags */
                        "Debug",            /* Argument string */
                        NULL,               /* Environment string */
                        &ReturnCodes,       /* Termination codes */
                        ProcessName);           /* Program file name */
        if (rc != NO_ERROR) {
            fprintf(hTrap,"rc = %d Process ID %d  Return Code %d \n",
                  rc,
                  ReturnCodes.codeTerminate,
                  ReturnCodes.codeResult);
            return;
        }
       fprintf(hTrap,"Connecting  to PID %d\n",ReturnCodes.codeTerminate);
       DbgBuf.Cmd = DBG_C_Connect; /* Indicate that a Connect is requested */
       DbgBuf.Pid = ReturnCodes.codeTerminate;
       DbgBuf.Tid = 0;
       DbgBuf.Value = DBG_L_386;
       rc = DosDebug(&DbgBuf);
       if (rc != 0) {
           fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
           fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
       }
       fprintf(hTrap,"Connected to PID %d\n",ReturnCodes.codeTerminate);
       /*****************************/
       pRec=(qsPtrRec_t *) pBuf;
       pLib=pRec->pLibRec;
       while (pLib) {
           GetObjects(&DbgBuf,pLib->hmte,pLib->pName);
           pLib =pLib->pNextRec;
       } /* endwhile */
     } else {
       fprintf(hTrap,"DosQProcStatus Failed %hd\n",rc16);
     } /* endif */
  } else {
     fprintf(hTrap,"DosAllocSeg Failed %hd\n",rc16);
  } /* endif */
#else
  PVOID BaseAddress;
  ULONG RegionSize;
  ULONG AllocationFlags;
  HMODULE LastModule;
  static CHAR Name[CCHMAXPATH];
  ULONG Size;
  LastModule=0;
  BaseAddress=(PVOID)0x10000;
  RegionSize =0x3FFFFFFF;
  fprintf(hTrap,"ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿\n");
  fprintf(hTrap,"³ List of currently accessed modules (DLLs) object addresses              ³");
  rc=DosQueryMem(BaseAddress,&RegionSize,&AllocationFlags);
  while (rc==NO_ERROR) {
     if ((AllocationFlags&PAG_EXECUTE)&&
         (AllocationFlags&PAG_BASE)) {
        rc=DOSQUERYMODFROMEIP( &hMod, &ObjNum, CCHMAXPATH,
                              Name, &Offset, BaseAddress);
        if (rc==0) {
            if (hMod!=LastModule) {
               rc=DosQueryModuleName(hMod,CCHMAXPATH, Name);
               fprintf(hTrap,"\nÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´\n");
               fprintf(hTrap,"³ Module %-48.48s Handle %8.8d ³\n",Name,hMod);
               fprintf(hTrap,"³ Object Number    Address    Length     Flags      Type                  ³");
               LastModule=hMod;
            } /* endif */
            fprintf(hTrap,"\n³       % 6.6d    %8.8lX   %8.8lX   %8.8lX ",ObjNum,
                      BaseAddress, RegionSize, AllocationFlags);
            rc16 =DOS16SIZESEG( SELECTOROF(BaseAddress), &Size);
            if (rc16==0) {
               fprintf(hTrap," - 16:16  Selector %4.4hX ³",SELECTOROF((PVOID)BaseAddress));
            } else {
               fprintf(hTrap," - 32 Bits              ³");
            } /* endif */
        }
     }
     if (AllocationFlags&PAG_FREE) RegionSize =0x10000;
     RegionSize +=0x0FFF;
     RegionSize &=0xFFFFF000;
     BaseAddress=(PVOID)(((PCHAR)BaseAddress)+RegionSize);
     RegionSize=((PCHAR)0x3FFFFFFF)-(PCHAR)BaseAddress;
     rc=DosQueryMem(BaseAddress,&RegionSize,&AllocationFlags);
     while ((rc==ERROR_INVALID_ADDRESS)||
            (rc==ERROR_NO_OBJECT)) {
         BaseAddress=(PVOID)(((PCHAR)BaseAddress)+0x10000);
         if (BaseAddress>(PVOID)0x3FFFFFFF) {
            break;
         } /* endif */
         RegionSize=((PCHAR)0x3FFFFFFF)-(PCHAR)BaseAddress;
         rc=DosQueryMem(BaseAddress,&RegionSize,&AllocationFlags);
     } /* endwhile */
     if (BaseAddress>(PVOID)0x3FFFFFFF) {
        break;
     } /* endif */
  } /* endwhile */
  fprintf(hTrap,"\nÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ\n");
#endif
}
#ifdef USE_DOSDEBUG
VOID  GetObjects(struct debug_buffer * pDbgBuf,HMODULE hMte,PSZ pName) {
    APIRET rc;
    int  object;
    pDbgBuf->MTE  = (ULONG) hMte;
    rc=0;
    fprintf(hTrap,"DLL %s Handle %d\n",pName,hMte);
    fprintf(hTrap,"Object Number    Address    Length     Flags      Type\n");
    for (object=1;object<256;object++ ) {
        pDbgBuf->Cmd   = DBG_C_NumToAddr;
        pDbgBuf->Pid   = ReturnCodes.codeTerminate;
        pDbgBuf->Value = object; /* Get nth object address in module with given MTE */
        pDbgBuf->Buffer= 0;
        pDbgBuf->Len   = 0;
        rc = DosDebug(pDbgBuf);
        if ((rc == NO_ERROR)&&
            (pDbgBuf->Cmd==NO_ERROR)) {
            ULONG Size;
            ULONG Flags;
            APIRET16 rc16;
            pDbgBuf->Len   = 0;
            pDbgBuf->Value = 0;
            if (pDbgBuf->Addr!=0) {
                pDbgBuf->Cmd   = DBG_C_AddrToObject;
                pDbgBuf->Pid   = ReturnCodes.codeTerminate;
                rc = DosDebug(pDbgBuf);
                if ((rc != NO_ERROR) ||
                    (pDbgBuf->Cmd|=NO_ERROR)) {
                   pDbgBuf->Len   = 0;
                   pDbgBuf->Value = 0;
                }
            }
            fprintf(hTrap,"      % 6.6d    %8.8lX   %8.8lX   %8.8lX ",object,
                      pDbgBuf->Addr, pDbgBuf->Len, pDbgBuf->Value);
            if (pDbgBuf->Addr!=0) {
                rc16 =DOS16SIZESEG( SELECTOROF(pDbgBuf->Addr), &Size);
                if (rc16==0) {
                   fprintf(hTrap," - 16:16  Selector %4.4hX\n",SELECTOROF((PVOID)pDbgBuf->Addr));
                } else {
                   fprintf(hTrap," - 32 Bits\n");
                } /* endif */
            } else {
               fprintf(hTrap," - ?\n");
            } /* endif */
        } else {
//         printf("DosDebug return code = %ld Notification %8.8lX\n", rc,pDbgBuf->Cmd);
//         printf("Value                = %8.8lX %ld\n",pDbgBuf->Value,pDbgBuf->Value);
           break;
        }
    } /* endfor */
    fprintf(hTrap,"\n");
}
#endif
void    CheckMem(PVOID Ptr,PSZ MemoryName) {
   APIRET rc;
   ULONG Size,Flags,Attr;
   Size=1;
   rc=DosQueryMem(Ptr,&Size,&Attr);
   if (rc!=NO_ERROR) {
      fprintf(hTrap,   "³ %3.3s does not point to valid memory ³\n",MemoryName);
   } else {
      if (Attr&PAG_FREE) {
         fprintf(hTrap,   "³ %3.3s points to unallocated memory   ³\n",MemoryName);
      } else {
         if ((Attr&PAG_COMMIT)==0x0U) {
            fprintf(hTrap,"³ %3.3s points to uncommited  memory   ³\n",MemoryName);
         } /* endif */
         if ((Attr&PAG_WRITE)==0x0U) {
            fprintf(hTrap,"³ %3.3s points to unwritable  memory   ³\n",MemoryName);
         } /* endif */
         if ((Attr&PAG_READ)==0x0U) {
            fprintf(hTrap,"³ %3.3s points to unreadable  memory   ³\n",MemoryName);
         } /* endif */
      } /* endif */
   } /* endif */
}
PUSHORT Convert(USHORT * _Seg16 p16) {
   return p16;
}
/* Better New WalkStack From John Currier */
static void WalkStack(PUSHORT StackBottom, PUSHORT StackTop, PUSHORT Ebp,
                      PUSHORT ExceptionAddress)
{
   PUSHORT  RetAddr;
   PUSHORT  LastEbp;
   APIRET   rc;
   ULONG    Size,Attr;
   USHORT   Cs,Ip,Bp,Sp;
   static char Name[CCHMAXPATH];
   HMODULE  hMod;
   ULONG    ObjNum;
   ULONG    Offset;
   BOOL     fExceptionAddress = TRUE;  // Use Exception Addr 1st time thru

   // Note: we can't handle stacks bigger than 64K for now...
   Sp = (USHORT)(((ULONG)StackBottom) >> 16);
   Bp = (USHORT)(ULONG)Ebp;

   if (!f32bit)
      Ebp = (PUSHORT)MAKEULONG(Bp, Sp);

   fprintf(hTrap,"\nCall Stack:\n");
   fprintf(hTrap,"                                        Source    Line      Nearest\n");
   fprintf(hTrap,"   EBP      Address    Module  Obj#      File     Numbr  Public Symbol\n");
   fprintf(hTrap," ÄÄÄÄÄÄÄÄ  ÄÄÄÄÄÄÄÄ-  ÄÄÄÄÄÄÄÄ ÄÄÄÄ  ÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄ-  ÄÄÄÄÄÄÄÄÄÄÄÄ-\n");

   do
   {
      Size = 10;
      rc = DosQueryMem((PVOID)(Ebp+2), &Size, &Attr);
      if (rc != NO_ERROR || !(Attr & PAG_COMMIT) ||  (Size<10) )
      {
         fprintf(hTrap,"Invalid EBP: %8.8p\n",Ebp);
         break;
      }

      if (fExceptionAddress)
         RetAddr = ExceptionAddress;
      else
         RetAddr = (PUSHORT)(*((PULONG)(Ebp+2)));

      if (RetAddr == (PUSHORT)0x00000053)
      {
         // For some reason there's a "return address" of 0x53 following
         // EBP on the stack and we have to adjust EBP by 44 bytes to get
         // at the real return address.  This has something to do with
         // thunking from 32bits to 16bits...
         // Serious kludge, and it's probably dependent on versions of C(++)
         // runtime or OS, but it works for now!
         Ebp += 22;
         RetAddr = (PUSHORT)(*((PULONG)(Ebp+2)));
      }

      // Get the (possibly) 16bit CS and IP
      if (fExceptionAddress)
      {
         Cs = (USHORT)(((ULONG)ExceptionAddress) >> 16);
         Ip = (USHORT)(ULONG)ExceptionAddress;
      }
      else
      {
         Cs = *(Ebp+2);
         Ip = *(Ebp+1);
      }

      // if the return address points to the stack then it's really just
      // a pointer to the return address (UGH!).
      if ((USHORT)(((ULONG)RetAddr) >> 16) == Sp)
         RetAddr = (PUSHORT)(*((PULONG)RetAddr));

      if (Ip == 0 && *Ebp == 0)
      {
         // End of the stack so these are both shifted by 2 bytes:
         Cs = *(Ebp+3);
         Ip = *(Ebp+2);
      }

      // 16bit programs have on the stack:
      //   BP:IP:CS
      //   where CS may be thunked
      //
      //         in dump                 swapped
      //    BP        IP   CS          BP   CS   IP
      //   4677      53B5 F7D0        7746 D0F7 B553
      //
      // 32bit programs have:
      //   EBP:EIP
      // and you'd have something like this (with SP added) (not
      // accurate values)
      //
      //         in dump               swapped
      //      EBP       EIP         EBP       EIP
      //   4677 2900 53B5 F7D0   0029 7746 D0F7 B553
      //
      // So the basic difference is that 32bit programs have a 32bit
      // EBP and we can attempt to determine whether we have a 32bit
      // EBP by checking to see if its 'selector' is the same as SP.
      // Note that this technique limits us to checking stacks < 64K.
      //
      // Soooo, if IP (which maps into the same USHORT as the swapped
      // stack page in EBP) doesn't point to the stack (i.e. it could
      // be a 16bit IP) then see if CS is valid (as is or thunked).
      //
      // Note that there's the possibility of a 16bit return address
      // that has an offset that's the same as SP so we'll think it's
      // a 32bit return address and won't be able to successfully resolve
      // its details.
      if (Ip != Sp)
      {
         if (DOS16SIZESEG(Cs, &Size) == NO_ERROR)
         {
            RetAddr = (USHORT * _Seg16)MAKEULONG(Ip, Cs);
            f32bit = FALSE;
         }
         else if (DOS16SIZESEG((Cs << 3) + 7, &Size) == NO_ERROR)
         {
            Cs = (Cs << 3) + 7;
            RetAddr = (USHORT * _Seg16)MAKEULONG(Ip, Cs);
            f32bit = FALSE;
         }
         else
            f32bit = TRUE;
      }
      else
         f32bit = TRUE;


      if (fExceptionAddress)
         fprintf(hTrap," Trap  ->");
      else
         fprintf(hTrap," %8.8p", Ebp);

      if (f32bit)
         fprintf(hTrap,"  :%8.8p", RetAddr);
      else
         fprintf(hTrap,"  %04.04X:%04.04X", Cs, Ip);

      if (Version[0] >= 20 && Version[1] >= 10)
      {
         // Make a 'tick' sound to let the user know we're still alive
         DosBeep(2000, 1);

         Size = 10; /* Inserted by Kim Rasmussen 26/06 1996 to avoid error 87 when Size is 0 */

         rc = DosQueryMem((PVOID)RetAddr, &Size, &Attr);
         if (rc != NO_ERROR || !(Attr & PAG_COMMIT))
         {
            fprintf(hTrap,"Invalid RetAddr: %8.8p\n",RetAddr);
            break; /* avoid infinite loops */
         } else {
            rc = DOSQUERYMODFROMEIP(&hMod, &ObjNum, sizeof(Name),
                                    Name, &Offset, (PVOID)RetAddr);
            if (rc == NO_ERROR && ObjNum != -1)
            {
               static char szJunk[_MAX_FNAME];
               static char szName[_MAX_FNAME];
               DosQueryModuleName(hMod, sizeof(Name), Name);
               _splitpath(Name, szJunk, szJunk, szName, szJunk);
               fprintf(hTrap,"  %-8s %04X", szName, ObjNum+1);

               if (strlen(Name) > 3)
               {
                  rc = GetLineNum(Name, ObjNum, Offset);
                  /* if no codeview try with symbol files */
                  if (rc != NO_ERROR)
                  {
                     strcpy(Name+strlen(Name)-3,"SYM");
                     GetSymbol(Name,ObjNum,Offset);
                  }
               }
            }
            else
            {
               fprintf(hTrap,"  *Unknown*");
            }
         }
      }

      fprintf(hTrap,"\n");

      Bp = *Ebp;
      if (Bp == 0 && (*Ebp+1) == 0)
      {
         fprintf(hTrap,"End of Call Stack\n");
         break;
      }

      if (!fExceptionAddress)
      {
         LastEbp = Ebp;
#if 0
         Ebp = (PUSHORT)MAKEULONG(Bp, Sp);
#else  /* Inserted by Kim Rasmussen 26/06 1996 to allow big stacks */
         if (f32bit)
            Ebp = (PUSHORT)*(PULONG)LastEbp;
         else
            Ebp = (PUSHORT)MAKEULONG(Bp, Sp);
#endif
         if (f32bit) {
             print_vars((ULONG)Ebp);
         } /* endif */

         if (Ebp < LastEbp)
         {
            fprintf(hTrap,"Lost Stack chain - new EBP below previous\n");
            break;
         }
      }
      else
         fExceptionAddress = FALSE;

      Size = 4;
      rc = DosQueryMem((PVOID)Ebp, &Size, &Attr);
      if ((rc != NO_ERROR)||(Size<4))
      {
         fprintf(hTrap,"Lost Stack chain - invalid EBP: %8.8p\n", Ebp);
         break;
      }
   } while (TRUE);

   fprintf(hTrap,"\n");
}

void GetSymbol(CHAR * SymFileName, ULONG Object,ULONG TrapOffset)
{
   static FILE * SymFile;
   static MAPDEF MapDef;
   static SEGDEF   SegDef;
   static SEGDEF *pSegDef;
   static SYMDEF32 SymDef32;
   static SYMDEF16 SymDef16;
   static char    Buffer[256];
   static int     SegNum,SymNum,LastVal;
   static unsigned long int SegOffset,SymOffset,SymPtrOffset;
   SymFile=fopen(SymFileName,"rb");
   if (SymFile==0) {
       /*fprintf(hTrap,"Could not open symbol file %s\n",SymFileName);*/
       return;
   } /* endif */
   fread(&MapDef,sizeof(MAPDEF),1,SymFile);
   SegOffset= SEGDEFOFFSET(MapDef);
   for (SegNum=0;SegNum<MapDef.cSegs;SegNum++) {
        /* printf("Scanning segment #%d Offset %4.4hX\n",SegNum+1,SegOffset); */
        if (fseek(SymFile,SegOffset,SEEK_SET)) {
           fprintf(hTrap,"Seek error ");
           return;
        }
        fread(&SegDef,sizeof(SEGDEF),1,SymFile);
        if (SegNum==Object) {
           Buffer[0]=0x00;
           LastVal=0;
           for (SymNum=0;SymNum<SegDef.cSymbols;SymNum++) {
              SymPtrOffset=SYMDEFOFFSET(SegOffset,SegDef,SymNum);
              fseek(SymFile,SymPtrOffset,SEEK_SET);
              fread(&SymOffset,sizeof(unsigned short int),1,SymFile);
              fseek(SymFile,SymOffset+SegOffset,SEEK_SET);
              if (SegDef.bFlags&0x01) {
                 fread(&SymDef32,sizeof(SYMDEF32),1,SymFile);
                 if (SymDef32.wSymVal>TrapOffset) {
                    fprintf(hTrap,"between %s + %X ",Buffer,TrapOffset-LastVal);
                 }
                 LastVal=SymDef32.wSymVal;
                 Buffer[0]= SymDef32.achSymName[0];
                 fread(&Buffer[1],1,SymDef32.cbSymName,SymFile);
                 Buffer[SymDef32.cbSymName]=0x00;
                 if (SymDef32.wSymVal>TrapOffset) {
                    fprintf(hTrap,"and %s - %X\n",Buffer,LastVal-TrapOffset);
                    break;
                 }
                 /*printf("32 Bit Symbol <%s> Address %p\n",Buffer,SymDef32.wSymVal);*/
              } else {
                 fread(&SymDef16,sizeof(SYMDEF16),1,SymFile);
                 if (SymDef16.wSymVal>TrapOffset) {
                    fprintf(hTrap,"between %s + %X ",Buffer,TrapOffset-LastVal);
                 }
                 LastVal=SymDef16.wSymVal;
                 Buffer[0]=SymDef16.achSymName[0];
                 fread(&Buffer[1],1,SymDef16.cbSymName,SymFile);
                 Buffer[SymDef16.cbSymName]=0x00;
                 if (SymDef16.wSymVal>TrapOffset) {
                    fprintf(hTrap,"and %s - %X\n",Buffer,LastVal-TrapOffset);
                    break;
                 }
                 /*printf("16 Bit Symbol <%s> Address %p\n",Buffer,SymDef16.wSymVal);*/
              } /* endif */
           }
           break;
        } /* endif */
        SegOffset=NEXTSEGDEFOFFSET(SegDef);
   } /* endwhile */
   fclose(SymFile);
}
VOID WakeThreads(VOID);
void APIENTRY ForceExit() {
    EXCEPTIONREPORTRECORD except;
    PCHAR  Trap;
    InForceExit =TRUE;
    fclose(stderr); /* I don't want error messages since all is intentional */
    DosError(FERR_DISABLEEXCEPTION | FERR_DISABLEHARDERR );
    DosEnterCritSec();
    WakeThreads();
    printf("Exiting by exception\n");
    Trap=NULL;
    DosSetPriority(PRTYS_THREAD,PRTYC_FOREGROUNDSERVER,PRTYD_MAXIMUM,0);
    DosExitCritSec();
    *Trap=0x00;
}
VOID WakeThreads() {
  APIRET   rc;
  APIRET16 rc16;
  qsPrec_t   * pProc;
  qsTrec_t   * pThread;
  ULONG      ListedThreads=0;
  PTIB   ptib;
  PPIB   ppib;
  DosGetInfoBlocks(&ptib,&ppib);
  /**----------------------------------***/
  rc16=DOS16ALLOCSEG( 0xFFFF , &Selector , 0);
  if (rc16==0) {
     pBuf=MAKEP(Selector,0);
     rc16=DOSQPROCSTATUS(pBuf, 0xFFFF );
     if (rc16==0) {
        /*****************************/
        pRec=(qsPtrRec_t *) pBuf;
        pProc =(qsPrec_t *)(pRec->pProcRec);
        ListedThreads=0;
        while (ListedThreads<pRec->pGlobalRec->cThrds) {
           int Tid;
           if (pProc->pThrdRec==NULL) break;
           ListedThreads+= pProc->cTCB;
           if (ppib->pib_ulpid==pProc->pid) {
              for (Tid=0;Tid<pProc->cTCB;Tid++ ) {
                 pThread =pProc->pThrdRec+Tid;
                 if (pThread->state==0x09) {
                    printf("Resuming Thread %d\n",(TID)pThread->tid);
                    DosResumeThread((TID)pThread->tid);
                 }
              } /* endfor */
              break;
           } /* endif  */
           pProc =(qsPrec_t *)( ((PUCHAR)pProc)
                                 +sizeof(qsPrec_t)
                                 +sizeof(USHORT)*(pProc->c16Sem+
                                                  pProc->cLib+
                                                  pProc->cShrMem)
                                 +(pProc->cTCB)*sizeof(qsTrec_t));

        } /* endwhile */
     } else {
        printf("DosQProcStatus Failed %hd\n",rc16);
     } /* endif */
  } else {
     printf("DosAllocSeg Failed %hd\n",rc16);
  } /* endif */
}
#include <exe.h>
#include <newexe.h>
#define  FOR_EXEHDR  1  /* avoid define conflicts between newexe.h and exe386.h */
#ifndef DWORD
#define DWORD long int
#endif
#ifndef WORD
#define WORD  short int
#endif
#include <exe386.h>
#include <fcntl.h>
#include <sys\stat.h>
#include <share.h>
#include <io.h>
/* ------------------------------------------------------------------ */
/* Last 8 bytes of 16:16 file when CODEVIEW debugging info is present */
#pragma pack(1)
 struct  _eodbug
        {
        unsigned short dbug;          /* 'NB' signature */
        unsigned short ver;           /* version        */
        unsigned long dfaBase;        /* size of codeview info */
        } eodbug;

#define         DBUGSIG         0x424E
#define         SSTMODULES      0x0101
#define         SSTPUBLICS      0x0102
#define         SSTTYPES        0x0103
#define         SSTSYMBOLS      0x0104
#define         SSTSRCLINES     0x0105
#define         SSTLIBRARIES    0x0106
#define         SSTSRCLINES2    0x0109
#define         SSTSRCLINES32   0x010B

 struct  _base
        {
        unsigned short dbug;          /* 'NB' signature */
        unsigned short ver;           /* version        */
        unsigned long lfoDir;   /* file offset to dir entries */
        } base;

 struct  ssDir
        {
        unsigned short sst;           /* SubSection Type */
        unsigned short modindex;      /* Module index number */
        unsigned long lfoStart;       /* Start of section */
        unsigned short cb;            /* Size of section */
        } ;

 struct  ssDir32
        {
        unsigned short sst;           /* SubSection Type */
        unsigned short modindex;      /* Module index number */
        unsigned long lfoStart;       /* Start of section */
        unsigned long  cb;            /* Size of section */
        } ;

 struct  ssModule
   {
   unsigned short          csBase;             /* code segment base */
   unsigned short          csOff;              /* code segment offset */
   unsigned short          csLen;              /* code segment length */
   unsigned short          ovrNum;             /* overlay number */
   unsigned short          indxSS;             /* Index into sstLib or 0 */
   unsigned short          reserved;
   char              csize;              /* size of prefix string */
   } ssmod;

 struct  ssModule32
   {
   unsigned short          csBase;             /* code segment base */
   unsigned long           csOff;              /* code segment offset */
   unsigned long           csLen;              /* code segment length */
   unsigned long           ovrNum;             /* overlay number */
   unsigned short          indxSS;             /* Index into sstLib or 0 */
   unsigned long           reserved;
   char                    csize;              /* size of prefix string */
   } ssmod32;

 struct  ssPublic
        {
        unsigned short  offset;
        unsigned short  segment;
        unsigned short  type;
        char      csize;
        } sspub;

 struct  ssPublic32
        {
        unsigned long   offset;
        unsigned short  segment;
        unsigned short  type;
        char      csize;
        } sspub32;

typedef  struct _SSLINEENTRY32 {
   unsigned short LineNum;
   unsigned short FileNum;
   unsigned long  Offset;
} SSLINEENTRY32;
typedef  struct _FIRSTLINEENTRY32 {
   unsigned short LineNum;
   unsigned char  entry_type;
   unsigned char  reserved;
   unsigned short numlines;
   unsigned short segnum;
} FIRSTLINEENTRY32;

typedef  struct _SSFILENUM32 {
    unsigned long first_displayable;  /* Not used */
    unsigned long number_displayable; /* Not used */
    unsigned long file_count;         /* number of source files */
} SSFILENUM32;

 struct  DbugRec {                       /* debug info struct ure used in linked * list */
    struct  DbugRec far *pnext;          /* next node *//* 013 */
   char far          *SourceFile;               /* source file name *013 */
   unsigned short          TypeOfProgram;       /* dll or exe *014* */
   unsigned short          LineNumber;          /* line number in source file */
   unsigned short          OffSet;              /* offset into loaded module */
   unsigned short          Selector;            /* code segment 014 */
   unsigned short          OpCode;              /* Opcode replaced with BreakPt */
   unsigned long     Count;                     /* count over Break Point */
};

typedef  struct  DbugRec DBUG, far * DBUGPTR;     /* 013 */
char szNrPub[128];
char szNrLine[128];
char szNrFile[128];
 struct  new_seg *pseg;
 struct  o32_obj *pobj;        /* Flat .EXE object table entry */
 struct  ssDir *pDirTab;
 struct  ssDir32 *pDirTab32;
unsigned char *pEntTab;
unsigned long lfaBase;
#pragma pack()
/* ------------------------------------------------------------------ */

APIRET GetLineNum(CHAR * FileName, ULONG Object,ULONG TrapOffset) {
   APIRET rc;
   int ModuleFile;
   static  struct  exe_hdr old;
   static  struct  new_exe new;
   static  struct  e32_exe e32;
   strcpy(szNrPub,"   N/A ");
   strcpy(szNrLine,"   N/A  ");
   strcpy(szNrFile,"             ");
   ModuleFile =sopen(FileName,O_RDONLY|O_BINARY,SH_DENYNO);
   if (ModuleFile!=-1) {
      /* Read old Exe header */
      if (read( ModuleFile ,(void *)&old,64)==-1L) {
        fprintf(hTrap,"Could Not Read old exe header %d\n",errno);
        close(ModuleFile);
        return 2;
      }
      /* Seek to new Exe header */
      if (lseek(ModuleFile,(long)E_LFANEW(old),SEEK_SET)==-1L) {
        fprintf(hTrap,"Could Not seek to new exe header %d\n",errno);
        close(ModuleFile);
        return 3;
      }
      if (read( ModuleFile ,(void *)&new,64)==-1L) {
        fprintf(hTrap,"Could Not read new exe header %d\n",errno);
        close(ModuleFile);
        return 4;
      }
      /* Check EXE signature */
      if (NE_MAGIC(new)==E32MAGIC) {
         /* Flat 32 executable */
         rc=Read32PmDebug(ModuleFile,Object+1,TrapOffset,FileName);
         if (rc==0) {
             fprintf(hTrap,"%s",szNrFile);
             fprintf(hTrap,"%s",szNrLine);
             fprintf(hTrap,"%s",szNrPub);
         } /* endif */
         close(ModuleFile);
         /* rc !=0 try with DBG file */
         if (rc!=0) {
            strcpy(FileName+strlen(FileName)-3,"DBG"); /* Build DBG File name */
            ModuleFile =sopen(FileName,O_RDONLY|O_BINARY,SH_DENYNO);
            if (ModuleFile!=-1) {
               rc=Read32PmDebug(ModuleFile,Object+1,TrapOffset,FileName);
               if (rc==0) {
                  fprintf(hTrap,"%s",szNrFile);
                  fprintf(hTrap,"%s",szNrLine);
                  fprintf(hTrap,"%s",szNrPub);
               } /* endif */
               close(ModuleFile);
            }
         } /* endif */
         return rc;
      } else {
         if (NE_MAGIC(new)==NEMAGIC) {
            /* 16:16 executable */
            if ((pseg = ( struct  new_seg *) calloc(NE_CSEG(new),sizeof( struct  new_seg)))==NULL) {
               fprintf(hTrap,"Out of memory!");
               close(ModuleFile);
               return -1;
            }
            if (lseek(ModuleFile,E_LFANEW(old)+NE_SEGTAB(new),SEEK_SET)==-1L) {
               fprintf(hTrap,"Error %u seeking segment table in %s\n",errno,FileName);
               free(pseg);
               close(ModuleFile);
               return 9;
            }

            if (read(ModuleFile,(void *)pseg,NE_CSEG(new)*sizeof( struct  new_seg))==-1) {
               fprintf(hTrap,"Error %u reading segment table from %s\n",errno,FileName);
               free(pseg);
               close(ModuleFile);
               return 10;
            }
            rc=Read16CodeView(ModuleFile,Object+1,TrapOffset,FileName);
            if (rc==0) {
               fprintf(hTrap,"%s",szNrFile);
               fprintf(hTrap,"%s",szNrLine);
               fprintf(hTrap,"%s",szNrPub);
            } /* endif */
            free(pseg);
            close(ModuleFile);
            /* rc !=0 try with DBG file */
            if (rc!=0) {
               strcpy(FileName+strlen(FileName)-3,"DBG"); /* Build DBG File name */
               ModuleFile =sopen(FileName,O_RDONLY|O_BINARY,SH_DENYNO);
               if (ModuleFile!=-1) {
                  rc=Read16CodeView(ModuleFile,Object+1,TrapOffset,FileName);
                  if (rc==0) {
                     fprintf(hTrap,"%s",szNrFile);
                     fprintf(hTrap,"%s",szNrLine);
                     fprintf(hTrap,"%s",szNrPub);
                  } /* endif */
                  close(ModuleFile);
               }
            } /* endif */
            return rc;

         } else {
            /* Unknown executable */
            fprintf(hTrap,"Could Not find exe signature");
            close(ModuleFile);
            return 11;
         }
      }
      /* Read new Exe header */
   } else {
      fprintf(hTrap,"Could Not open Module File %d",errno);
      return 1;
   } /* endif */
   return 0;
}
char fname[128],ModName[80];
char ename[128],dummy[128];
int Read16CodeView(int fh,int TrapSeg,int TrapOff,CHAR * FileName) {
    static unsigned short int offset,NrPublic,NrLine,NrEntry,numdir,namelen,numlines,line;
    static int ModIndex;
    static int bytesread,i,j;
    ModIndex=0;
    /* See if any CODEVIEW info */
    if (lseek(fh,-8L,SEEK_END)==-1) {
        fprintf(hTrap,"Error %u seeking CodeView table in %s\n",errno,FileName);
        return(18);
    }

    if (read(fh,(void *)&eodbug,8)==-1) {
       fprintf(hTrap,"Error %u reading debug info from %s\n",errno,FileName);
       return(19);
    }
    if (eodbug.dbug!=DBUGSIG) {
       /* fprintf(hTrap,"\nNo CodeView information stored.\n"); */
       return(100);
    }

    if ((lfaBase=lseek(fh,-eodbug.dfaBase,SEEK_END))==-1L) {
       fprintf(hTrap,"Error %u seeking base codeview data in %s\n",errno,FileName);
       return(20);
    }

    if (read(fh,(void *)&base,8)==-1) {
       fprintf(hTrap,"Error %u reading base codeview data in %s\n",errno,FileName);
       return(21);
    }

    if (lseek(fh,base.lfoDir-8,SEEK_CUR)==-1) {
       fprintf(hTrap,"Error %u seeking dir codeview data in %s\n",errno,FileName);
       return(22);
    }

    if (read(fh,(void *)&numdir,2)==-1) {
       fprintf(hTrap,"Error %u reading dir codeview data in %s\n",errno,FileName);
       return(23);
    }

    /* Read dir table into buffer */
    if (( pDirTab = ( struct  ssDir *) calloc(numdir,sizeof( struct  ssDir)))==NULL) {
       fprintf(hTrap,"Out of memory!");
       return(-1);
    }

    if (read(fh,(void *)pDirTab,numdir*sizeof( struct  ssDir))==-1) {
       fprintf(hTrap,"Error %u reading codeview dir table from %s\n",errno,FileName);
       free(pDirTab);
       return(24);
    }

    i=0;
    while (i<numdir) {
       if (pDirTab[i].sst!=SSTMODULES) {
           i++;
           continue;
       }
       NrPublic=0x0;
       NrLine=0x0;
       /* point to subsection */
       lseek(fh, pDirTab[i].lfoStart + lfaBase, SEEK_SET);
       read(fh,(void *)&ssmod.csBase,sizeof(ssmod));
       read(fh,(void *)ModName,(unsigned)ssmod.csize);
       ModIndex=pDirTab[i].modindex;
       ModName[ssmod.csize]='\0';
       i++;
       while (pDirTab[i].modindex ==ModIndex && i<numdir) {
          /* point to subsection */
          lseek(fh, pDirTab[i].lfoStart + lfaBase, SEEK_SET);
          switch(pDirTab[i].sst) {
            case SSTPUBLICS:
               bytesread=0;
               while (bytesread < pDirTab[i].cb) {
                   bytesread += read(fh,(void *)&sspub.offset,sizeof(sspub));
                   bytesread += read(fh,(void *)ename,(unsigned)sspub.csize);
                   ename[sspub.csize]='\0';
                   if ((sspub.segment==TrapSeg) &&
                       (sspub.offset<=TrapOff) &&
                       (sspub.offset>=NrPublic)) {
                       NrPublic=sspub.offset;
                       sprintf(szNrPub,"%s %s (%s) %04hX:%04hX\n",
                               (sspub.type==1) ? " Abs" : " ",ename,ModName,
                               sspub.segment, sspub.offset
                               );
                   }
               }
               break;

            case SSTSRCLINES2:
            case SSTSRCLINES:
               if (TrapSeg!=ssmod.csBase) break;
               namelen=0;
               read(fh,(void *)&namelen,1);
               read(fh,(void *)ename,namelen);
               ename[namelen]='\0';
               /* skip 2 zero bytes */
               if (pDirTab[i].sst==SSTSRCLINES2) read(fh,(void *)&numlines,2);
               read(fh,(void *)&numlines,2);
               for (j=0;j<numlines;j++) {
                  read(fh,(void *)&line,2);
                  read(fh,(void *)&offset,2);
                  if (offset<=TrapOff && offset>=NrLine) {
                     NrLine=offset;
                     sprintf(szNrLine,"% 6hu", line);
                     sprintf(szNrFile,"%  13.13s ", ename);
                     /*sprintf(szNrLine,"%04hX:%04hX  line #%hu  (%s) (%s)\n",
                             ssmod.csBase,offset,line,ModName,ename); */
                  }
               }
               break;
          } /* end switch */
          i++;
       } /* end while modindex */
    } /* End While i < numdir */
    free(pDirTab);
    return(0);
}

#define MAX_USERDEFS 150
#define MAX_POINTERS 150

USHORT userdef_count;
USHORT pointer_count;

struct one_userdef_rec {
   USHORT idx;
   USHORT type_index;
   BYTE   name[33];
} one_userdef[MAX_USERDEFS];

struct one_pointer_rec {
   USHORT idx;
   USHORT type_index;
   BYTE   type_qual;
   BYTE   name[33];
} one_pointer[MAX_POINTERS];

int Read32PmDebug(int fh,int TrapSeg,int TrapOff,CHAR * FileName) {
    static unsigned int CurrSymSeg, NrSymbol,offset,NrPublic,NrFile,NrLine,NrEntry,numdir,namelen,numlines,line;
    static int ModIndex;
    static int bytesread,i,j;
    static int pOffset;
    static SSLINEENTRY32 LineEntry;
    static SSFILENUM32 FileInfo;
    static FIRSTLINEENTRY32 FirstLine;
    static BYTE dump_vars = FALSE;
    static USHORT idx;
    static BOOL read_types;
    static LONG lSize;
    static BOOL is_new_debug;

    ModIndex=0;
    /* See if any CODEVIEW info */
    if (lseek(fh,-8L,SEEK_END)==-1) {
        fprintf(hTrap,"Error %u seeking CodeView table in %s\n",errno,FileName);
        return(18);
    }

    if (read(fh,(void *)&eodbug,8)==-1) {
       fprintf(hTrap,"Error %u reading debug info from %s\n",errno,FileName);
       return(19);
    }
    if (eodbug.dbug!=DBUGSIG) {
       /*fprintf(hTrap,"\nNo CodeView information stored.\n");*/
       return(100);
    }

    if ((lfaBase=lseek(fh,-eodbug.dfaBase,SEEK_END))==-1L) {
       fprintf(hTrap,"Error %u seeking base codeview data in %s\n",errno,FileName);
       return(20);
    }

    if (read(fh,(void *)&base,8)==-1) {
       fprintf(hTrap,"Error %u reading base codeview data in %s\n",errno,FileName);
       return(21);
    }

    if (lseek(fh,base.lfoDir-8+4,SEEK_CUR)==-1) {
       fprintf(hTrap,"Error %u seeking dir codeview data in %s\n",errno,FileName);
       return(22);
    }

    if (read(fh,(void *)&numdir,4)==-1) {
       fprintf(hTrap,"Error %u reading dir codeview data in %s\n",errno,FileName);
       return(23);
    }

    /* Read dir table into buffer */
    if (( pDirTab32 = ( struct  ssDir32 *) calloc(numdir,sizeof( struct  ssDir32)))==NULL) {
       fprintf(hTrap,"Out of memory!");
       return(-1);
    }

    if (read(fh,(void *)pDirTab32,numdir*sizeof( struct  ssDir32))==-1) {
       fprintf(hTrap,"Error %u reading codeview dir table from %s\n",errno,FileName);
       free(pDirTab32);
       return(24);
    }

    i=0;
    while (i<numdir) {
       if ( pDirTab32[i].sst !=SSTMODULES) {
           i++;
           continue;
       }
       NrPublic=0x0;
       NrSymbol=0;
       NrLine=0x0;
       NrFile=0x0;
       CurrSymSeg = 0;
       /* point to subsection */
       lseek(fh, pDirTab32[i].lfoStart + lfaBase, SEEK_SET);
       read(fh,(void *)&ssmod32.csBase,sizeof(ssmod32));
       read(fh,(void *)ModName,(unsigned)ssmod32.csize);
       ModIndex=pDirTab32[i].modindex;
       ModName[ssmod32.csize]='\0';
       i++;

       read_types = FALSE;

       while (pDirTab32[i].modindex ==ModIndex && i<numdir) {
          /* point to subsection */
          lseek(fh, pDirTab32[i].lfoStart + lfaBase, SEEK_SET);
          switch(pDirTab32[i].sst) {
            case SSTPUBLICS:
               bytesread=0;
               while (bytesread < pDirTab32[i].cb) {
                   bytesread += read(fh,(void *)&sspub32.offset,sizeof(sspub32));
                   bytesread += read(fh,(void *)ename,(unsigned)sspub32.csize);
                   ename[sspub32.csize]='\0';
                   if ((sspub32.segment==TrapSeg) &&
                       (sspub32.offset<=TrapOff) &&
                       (sspub32.offset>=NrPublic)) {
                       NrPublic = pubfunc_ofs = sspub32.offset;
                       read_types = TRUE;
                       sprintf(szNrPub,"%s %s (%s) %04X:%08X\n",
                               (sspub32.type==1) ? " Abs" : " ",ename,ModName,
                               sspub32.segment, sspub32.offset
                               );
                   }
               }
               break;

            /* Read symbols, so we can dump the variables on the stack */
            case SSTSYMBOLS:
               if (TrapSeg!=ssmod32.csBase) break;

               bytesread=0;
               while (bytesread < pDirTab32[i].cb) {
                  static USHORT usLength;
                  static BYTE b1, b2;
                  static BYTE bType, *ptr;
                  static ULONG ofs;
                  static ULONG last_addr = 0;
                  static BYTE str[256];
                  static struct symseg_rec       symseg;
                  static struct symauto_rec      symauto;
                  static struct symproc_rec      symproc;

                  /* Read the length of this subentry */
                  bytesread += read(fh, &b1, 1);
                  if (b1 & 0x80) {
                     bytesread += read(fh, &b2, 1);
                     usLength = ((b1 & 0x7F) << 8) + b2;
                  }
                  else
                     usLength = b1;

                  ofs = tell(fh);

                  bytesread += read(fh, &bType, 1);

                  switch(bType) {
                     case SYM_CHANGESEG:
                        read(fh, &symseg, sizeof(symseg));
                        CurrSymSeg = symseg.seg_no;
                        break;

                     case SYM_PROC:
                     case SYM_CPPPROC:
                        read(fh, &symproc, sizeof(symproc));
                        read(fh, str, symproc.name_len);
                           str[symproc.name_len] = 0;

                        if ((CurrSymSeg == TrapSeg) &&
                            (symproc.offset<=TrapOff) &&
                            (symproc.offset>=NrSymbol)) {

                           dump_vars = TRUE;
                           var_ofs = 0;
                           NrSymbol = symproc.offset;
                           func_ofs = symproc.offset;

                           strcpy(func_name, str);
                        }
                        else {
                           dump_vars = FALSE;
                        }
                        break;

                     case SYM_AUTO:
                        if (!dump_vars)
                           break;

                        read(fh, &symauto, sizeof(symauto));
                        read(fh, str, symauto.name_len);
                        str[symauto.name_len] = 0;

                        strcpy(autovar_def[var_ofs].name, str);
                        autovar_def[var_ofs].stack_offset = symauto.stack_offset;
                        autovar_def[var_ofs].type_idx = symauto.type_idx;
                        var_ofs++;
                        break;

                  }

                  bytesread += usLength;

                  lseek(fh, ofs+usLength, SEEK_SET);
               }
               break;

            case SSTTYPES:
//               if (ModIndex != TrapSeg)
               if (!read_types)
                  break;

               bytesread=0;
               idx = 0x200;
               userdef_count = 0;
               pointer_count = 0;
               while (bytesread < pDirTab32[i].cb) {
                  static struct type_rec         type;
                  static struct type_userdefrec  udef;
                  static struct type_pointerrec  point;
                  static struct type_funcrec     func;
                  static struct type_structrec   struc;
                  static struct type_list1       list1;
                  static struct type_list2       list2;
                  static struct type_list2_1     list2_1;
                  static ULONG  ofs;
                  static BYTE   str[256], b1, b2;
                  static USHORT n;

                  /* Read the length of this subentry */
                  ofs = tell(fh);

                  read(fh, &type, sizeof(type));
                  bytesread += sizeof(type);

                  switch(type.type) {
                     case TYPE_USERDEF:
                        if (userdef_count > MAX_USERDEFS)
                           break;

                        read(fh, &udef, sizeof(udef));
                        read(fh, str, udef.name_len);
                        str[udef.name_len] = 0;

                        // Insert userdef in table
                        one_userdef[userdef_count].idx = idx;
                        one_userdef[userdef_count].type_index = udef.type_index;
                        memcpy(one_userdef[userdef_count].name, str, min(udef.name_len+1, 32));
                        one_userdef[userdef_count].name[32] = 0;
                        userdef_count++;
                        break;

                     case TYPE_POINTER:
                        if (pointer_count > MAX_POINTERS)
                           break;

                        read(fh, &point, sizeof(point));
                        read(fh, str, point.name_len);
                        str[point.name_len] = 0;

                        // Insert userdef in table
                        one_pointer[pointer_count].idx = idx;
                        one_pointer[pointer_count].type_index = point.type_index;
                        memcpy(one_pointer[pointer_count].name, str, min(point.name_len+1, 32));
                        one_pointer[pointer_count].name[32] = 0;
                        one_pointer[pointer_count].type_qual = type.type_qual;
                        pointer_count++;
                        break;
                  }

                  ++idx;

                  bytesread += type.length;

                  lseek(fh, ofs+type.length+2, SEEK_SET);
               }
               break;

            case SSTSRCLINES32:
               if (TrapSeg!=ssmod32.csBase) break;

               /* read first line */
               do {
                  read(fh,(void *)&FirstLine,sizeof(FirstLine));
   
                  if (FirstLine.LineNum!=0) {
                     fprintf(hTrap,"Missing Line table information\n");
                     break;
                  } /* endif */
                  numlines= FirstLine.numlines;
                  /* Other type of data skip 4 more bytes */
                  if (FirstLine.entry_type < 4) {
                     read(fh, (void *)&lSize, 4);
                     if (FirstLine.entry_type == 3)
                        lseek(fh,lSize,SEEK_CUR);
                  }
               } while(FirstLine.entry_type == 3);

               for (j=0;j<numlines;j++) {
                  switch (FirstLine.entry_type) {
                     case 0:
                        read(fh,(void *)&LineEntry,sizeof(LineEntry));
                        /* Changed by Kim Rasmussen 26/06 1996 to ignore linenumber 0 */
         /*               if (LineEntry.Offset+ssmod32.csOff<=TrapOff && LineEntry.Offset+ssmod32.csOff>=NrLine) { */
                        if (LineEntry.LineNum && LineEntry.Offset+ssmod32.csOff<=TrapOff && LineEntry.Offset+ssmod32.csOff>=NrLine) {
                           NrLine=LineEntry.Offset;
                           NrFile=LineEntry.FileNum;
                           /*pOffset =sprintf(szNrLine,"%04X:%08X  line #%hu ",
                                   ssmod32.csBase,LineEntry.Offset,
                                   LineEntry.LineNum);*/
                          sprintf(szNrLine,"% 6hu", LineEntry.LineNum);
                        }
                        break;
   
                     case 1:
                        lseek(fh, sizeof(struct linlist_rec), SEEK_CUR);
                        break;
   
                     case 2:
                        lseek(fh, sizeof(struct linsourcelist_rec), SEEK_CUR);
                        break;
   
                     case 3:
                        lseek(fh, sizeof(struct filenam_rec), SEEK_CUR);
                        break;
   
                     case 4:
                        lseek(fh, sizeof(struct pathtab_rec), SEEK_CUR);
                        break;
   
                  }
               }

               
               if (NrFile!=0) {
                  read(fh,(void *)&FileInfo,sizeof(FileInfo));
                  namelen=0;
                  for (j=1;j<=FileInfo.file_count;j++) {
                     namelen=0;
                     read(fh,(void *)&namelen,1);
                     read(fh,(void *)ename,namelen);
                     if (j==NrFile) break;
                  }
                  ename[namelen]='\0';
                  /*  pOffset=sprintf(szNrLine+pOffset," (%s) (%s)\n",ename,ModName);*/
                  sprintf(szNrFile,"%  13.13s ",ename);
               } else {
                  /* strcat(szNrLine,"\n"); avoid new line for empty name fill */
                 strcpy(szNrFile,"             ");
               } /* endif */
               break;
          } /* end switch */

          i++;
       } /* end while modindex */
    } /* End While i < numdir */
    free(pDirTab32);
    return(0);
}

BYTE *var_value(void *varptr, BYTE type)
{
   static BYTE value[128];
   APIRET rc;

   strcpy(value, "Unknown");

   if (type == 0)
      sprintf(value, "%hd", *(signed char *)varptr);
   else if (type == 1)
      sprintf(value, "%hd", *(signed short *)varptr);
   else if (type == 2)
      sprintf(value, "%ld", *(signed long *)varptr);
   else if (type == 4)
      sprintf(value, "%hu", *(BYTE *)varptr);
   else if (type == 5)
      sprintf(value, "%hu", *(USHORT *)varptr);
   else if (type == 6)
      sprintf(value, "%lu", *(ULONG *)varptr);
   else if (type == 8)
      sprintf(value, "%f", *(float *)varptr);
   else if (type == 9)
      sprintf(value, "%f", *(double *)varptr);
   else if (type == 10)
      sprintf(value, "%f", *(long double *)varptr);
   else if (type == 16)
      sprintf(value, "%s", *(char *)varptr ? "TRUE" : "FALSE");
   else if (type == 17)
      sprintf(value, "%s", *(short *)varptr ? "TRUE" : "FALSE");
   else if (type == 18)
      sprintf(value, "%s", *(long *)varptr ? "TRUE" : "FALSE");
   else if (type == 20)
      sprintf(value, "%c", *(char *)varptr);
   else if (type == 21)
      sprintf(value, "%lc", *(short *)varptr);
   else if (type == 22)
      sprintf(value, "%lc", *(long *)varptr);
   else if (type == 23)
      sprintf(value, "void");
   else if (type >= 32) {
      ULONG Size,Attr;
      Size=1;
      rc=DosQueryMem((void*)*(ULONG *)varptr,&Size,&Attr);
      if (rc) {
         sprintf(value, "0x%p invalid", *(ULONG *)varptr);
      } else {
         sprintf(value, "0x%p", *(ULONG *)varptr);
         if (Attr&PAG_FREE) {
            strcat(value," unallocated memory");
         } else {
            if ((Attr&PAG_COMMIT)==0x0U) {
               strcat(value," uncommited");
            } /* endif */
            if ((Attr&PAG_WRITE)==0x0U) {
               strcat(value," unwritable");
            } /* endif */
            if ((Attr&PAG_READ)==0x0U) {
               strcat(value," unreadable");
            } /* endif */
         } /* endif */
      } /* endif */
   }

   return value;
}

/* Search the table of userdef's - return TRUE if found */
BOOL search_userdefs(ULONG stackofs, USHORT var_no)
{
   USHORT pos;

   for(pos = 0; pos < userdef_count && one_userdef[pos].idx != autovar_def[var_no].type_idx; pos++);

   if (pos < userdef_count) {
      if (one_userdef[pos].type_index >= 0x80 && one_userdef[pos].type_index <= 0xDA) {
         fprintf(hTrap, "%- 6d %- 20.20s %- 33.33s %s\n",
                 autovar_def[var_no].stack_offset,
                 autovar_def[var_no].name,
                 one_userdef[pos].name,
                 var_value((void *)(stackofs+autovar_def[var_no].stack_offset),
                           one_userdef[pos].type_index-0x80));
         return TRUE;
      }
      else /* If the result isn't a simple type, let's act as we didn't find it */
         return FALSE;
   }

   return FALSE;
}

BOOL search_pointers(ULONG stackofs, USHORT var_no)
{
   USHORT pos, upos;
   static BYTE str[35];
   BYTE   type_index;

   for(pos = 0; pos < pointer_count && one_pointer[pos].idx != autovar_def[var_no].type_idx; pos++);

   if (pos < pointer_count) {
      if (one_pointer[pos].type_index >= 0x80 && one_pointer[pos].type_index <= 0xDA) {
         strcpy(str, type_name[one_pointer[pos].type_index-0x80]);
         strcat(str, " *");
         fprintf(hTrap, "%- 6d %- 20.20s %- 33.33s %s\n",
                 autovar_def[var_no].stack_offset,
                 autovar_def[var_no].name,
                 str,
                 var_value((void *)(stackofs+autovar_def[var_no].stack_offset), 32));
         return TRUE;
      }
      else { /* If the result isn't a simple type, look for it in the other lists */
         for(upos = 0; upos < userdef_count && one_userdef[upos].idx != one_pointer[pos].type_index; upos++);

         if (upos < userdef_count) {
            strcpy(str, one_userdef[upos].name);
            strcat(str, " *");
            fprintf(hTrap, "%- 6d %- 20.20s %- 33.33s %s\n",
                    autovar_def[var_no].stack_offset,
                    autovar_def[var_no].name,
                    str,
                    var_value((void *)(stackofs+autovar_def[var_no].stack_offset), 32));
            return TRUE;
         }
         else { /* If it isn't a userdef, for now give up and just print as much as we know */
            sprintf(str, "Pointer to type 0x%X", one_pointer[pos].type_index);

            fprintf(hTrap, "%- 6d %- 20.20s %- 33.33s %s\n",
                    autovar_def[var_no].stack_offset,
                    autovar_def[var_no].name,
                    str,
                    var_value((void *)(stackofs+autovar_def[var_no].stack_offset), 32));

            return TRUE;
         }
      }
   }

   return FALSE;
}

void print_vars(ULONG stackofs)
{
   USHORT n, pos;
   BOOL   AutoVarsFound=FALSE;

/*   stackofs += stack_ebp; */
   if (1 || func_ofs == pubfunc_ofs) {
      for(n = 0; n < var_ofs; n++) {
         if (AutoVarsFound==FALSE) {
             AutoVarsFound=TRUE;
             fprintf(hTrap, "List of auto variables at EBP %p in %s:\n",stackofs, func_name);
             fprintf(hTrap,"Offset Name                 Type                              Value            \n");
             fprintf(hTrap,"ÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ\n");
         }

         /* If it's one of the simple types */
         if (autovar_def[n].type_idx >= 0x80 && autovar_def[n].type_idx <= 0xDA)
         {
            fprintf(hTrap, "%- 6d %- 20.20s %- 33.33s %s\n",
                    autovar_def[n].stack_offset,
                    autovar_def[n].name,
                    type_name[autovar_def[n].type_idx-0x80],
                    var_value((void *)(stackofs+autovar_def[n].stack_offset),
                              autovar_def[n].type_idx-0x80));
         }
         else { /* Complex type, check if we know what it is */
            if (!search_userdefs(stackofs, n)) {
               if (!search_pointers(stackofs, n)) {
                  fprintf(hTrap, "%- 6d %-20.20s 0x%X\n",
                                 autovar_def[n].stack_offset,
                                 autovar_def[n].name,
                                 autovar_def[n].type_idx);
               }
            }
         }
      }
      if (AutoVarsFound==FALSE) {
          fprintf(hTrap, "  No auto variables found in %s.\n", func_name);
      }
      fprintf(hTrap, "\n");
   }
}
