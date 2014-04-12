/**********************************************************************/
/*                           IBM Internal Use Only                    */
/**********************************************************************/
/*                                                                    */
/*  TRAPTRAP                                                          */
/*                                                                    */
/* TRAPTRAP is a sample usage of DosDebug to gather information       */
/* on program traps without changing the source code.                 */
/* C-SET/2 compiler complies that code                                */
/**********************************************************************/
/* Version: 2.4             |   Marc Fiammante (FIAMMANT at LGEVMA)   */
/*                          |   La Gaude FRANCE                       */
/*                          |   Internet: fiammante@vnet.ibm.com      */
/* Version: 2.5             |   Anthony Cruise (CRUISE at YKTVMH)     */
/*                          |   Watson Research                       */
/* Version: 6.2             |   Marc Fiammante (FIAMMANT at LGEVMA)   */
/*                          |   La Gaude FRANCE                       */
/*                          |   Internet: fiammante@vnet.ibm.com      */
/**********************************************************************/
/* Test only under OS/2 version 2.1                                   */
/**********************************************************************/
/* History:                                                           */
/* --------                                                           */
/*                                                                    */
/* created: Marc Fiammante September 1993                             */
/*      this traptrap.c uses DosStartSession which allows any kind    */
/*           of executables PM,TextWindowed or FullScreen             */
/* changed: Anthony Cruise, May 1995                                  */
/*    Do not dump duplicate lines                                     */
/* changed: Marc Fiammante, July 1995                                 */
/*    Put in WalkStack and other goodies                              */
/**********************************************************************/
#define INCL_BASE
#include <os2.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "sym.h"
#include "omf.h"
/*-------- Various Buffers and pointers ------*/
CHAR   CmdBuf[256];
CHAR   ObjectBuffer[256];
CHAR   *CmdPtr;
UCHAR  LoadError[40]; /*DosExecPGM buffer */
UCHAR  ProcessName[256];
CHAR   Name[CCHMAXPATH];
UCHAR  *StackCopy;
FILE   *hTrap;
/*-------- Stack and symbolic walk      ------*/
static void WalkStack(PUSHORT StackBottom,PUSHORT StackTop,PUSHORT Ebp,PUSHORT ExceptionAddress);
int    Read16CodeView(int fh,int TrapSeg,int TrapOff,CHAR * FileName);
int    Read32PmDebug(int fh,int TrapSeg,int TrapOff,CHAR * FileName);
APIRET GetLineNum(CHAR * FileName, ULONG Object,ULONG TrapOffset);
void GetSymbol(CHAR * SymFileName, ULONG Object,ULONG TrapOffset);
void print_vars(ULONG stackofs);
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

ULONG func_ofs;
ULONG pubfunc_ofs;
char  func_name[128];
ULONG var_ofs = 0;

struct {
   BYTE name[128];
   ULONG stack_offset;
   USHORT type_idx;
} autovar_def[100];

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
static BOOL   f32bit;

/*============================================*/
/*--ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»  ------*/
/*--º DosDebug Definitions           º  ------*/
/*--ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼  ------*/
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
/*---- Commands -----------------------*/
#define DBG_C_NULL                 0
#define DBG_C_ReadMem              1
#define DBG_C_ReadMem_I            1
#define DBG_C_ReadMem_D            2
#define DBG_C_ReadReg              3
#define DBG_C_WriteMem             4
#define DBG_C_WriteMem_I           4
#define DBG_C_WriteMem_D           5
#define DBG_C_WriteReg             6
#define DBG_C_Go                   7
#define DBG_C_Term                 8
#define DBG_C_SStep                9
#define DBG_C_Stop                 10
#define DBG_C_Freeze               11
#define DBG_C_Resume               12
#define DBG_C_NumToAddr            13
#define DBG_C_ReadCoRegs           14
#define DBG_C_WriteCoRegs          15
#define DBG_C_ThrdStat             17
#define DBG_C_MapROAlias           18
#define DBG_C_MapRWAlias           19
#define DBG_C_UnMapALias           20
#define DBG_C_Connect              21
#define DBG_C_ReadMemBuf           22
#define DBG_C_WriteMemBuf          23
#define DBG_C_SetWatch             24
#define DBG_C_ClearWatch           25
#define DBG_C_RangeStep            26
#define DBG_C_Continue             27
#define DBG_C_AddrToObject         28
#define DBG_C_XchngOpCode          29
#define DBG_C_LinToSel             30
#define DBG_C_SelToLin             31
/*------ Constants -------------------*/
#define DBG_L_386                   1
#define DBG_O_OBJMTE       0x10000000L
/*------ Notifications ---------------*/
#define DBG_N_SUCCESS               0
#define DBG_N_ERROR                -1
#define DBG_N_ProcTerm             -6
#define DBG_N_Exception            -7
#define DBG_N_ModuleLoad           -8
#define DBG_N_CoError              -9
#define DBG_N_ThreadTerm           -10
#define DBG_N_AsyncStop            -11
#define DBG_N_NewProc              -12
#define DBG_N_AliasFree            -13
#define DBG_N_Watchpoint           -14
#define DBG_N_ThreadCreate         -15
#define DBG_N_ModuleFree           -16
#define DBG_N_RangeStep            -17
#define DBG_X_FIRST_CHANCE          1
#define DBG_X_STACK_INVALID         3
#define DBG_W_Local                0x00000001
#define DBG_W_Global               0x00000002
#define DBG_W_Execute              0x00010000
#define DBG_W_Write                0x00020000
#define DBG_W_ReadWrite            0x00030000
RESULTCODES ReturnCodes;
APIRET CheckExcep( PEXCEPTIONREPORTRECORD       pERepRec,
                   PCONTEXTRECORD               pCtxRec);
/*-------------------------------------*/
CHAR    Buffer[CCHMAXPATH];

typedef ULONG     * _Seg16 PULONG16;
APIRET16 APIENTRY16 DOS16SIZESEG( USHORT Seg , PULONG16 Size);
typedef  APIRET16  (APIENTRY16  _PFN16)();
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
VOID ListModules(VOID);
VOID  GetObjects(struct debug_buffer * pDbgBuf,HMODULE hMte,PSZ pName);
CHAR *QueueName="\\QUEUES\\TRACE\\TRACE.QUE";
HQUEUE QueueHandle=0;
USHORT WatchPointCount=0;
ULONG  WatchPoint[4];
ULONG  WatchIndex[4];
char * stopstring;
typedef struct _LOADEDMODS {
     struct  _LOADEDMODS * Next;
     HMODULE hMte;
} LOADEDMODS;
typedef LOADEDMODS * PLOADEDMODS;
PLOADEDMODS FirstLoaded=0;
PLOADEDMODS LastLoaded;
BOOL BigSeg;
ULONG   ObjNum;
ULONG   Offset;
ULONG   CodeAddress;
PUSHORT StackBase;

APIRET APIENTRY DbgQueryModFromEIP( HMODULE *phMod,
                                    ULONG *pObjNum,
                                    ULONG NameLen,
                                    PCHAR Name,
                                    ULONG *pOffset,
                                    PVOID Address )
                          {
    ULONG   pObject;
    APIRET  rc;
    DbgBuf.Cmd = DBG_C_AddrToObject;/* Indicate that a AddrToObject is requested */
    DbgBuf.Addr=(ULONG)Address;
    DbgBuf.Pid = ReturnCodes.codeTerminate; /* Pid of Debuggee */
    rc = DosDebug(&DbgBuf);
    if (rc != 0) {
        fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
        fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
        return 1;
    }
    pObject=DbgBuf.Buffer;
    *pOffset=((ULONG)Address)-pObject;
    for (*pObjNum=1;(*pObjNum)<256;(*pObjNum)++) {
        DbgBuf.Cmd   = DBG_C_NumToAddr;
        DbgBuf.Pid   = ReturnCodes.codeTerminate;
        DbgBuf.Value = *pObjNum; /* Get nth object address in module with given MTE */
        DbgBuf.Buffer= 0;
        DbgBuf.Len   = 0;
        rc = DosDebug(&DbgBuf);
        if ((rc == NO_ERROR)&&
            (DbgBuf.Cmd==NO_ERROR)) {
             if (DbgBuf.Addr==pObject) {
                break;
             } /* endif */
        } else {
           break;
        }
    } /* endfor */
    if (*pObjNum>=256) {
       *pObjNum=-1;
       fprintf(hTrap,"BAD !!\n");
       return 2;
    } else {
       *pObjNum-=1;
    }
    *phMod=DbgBuf.MTE;
    rc=DosQueryModuleName(DbgBuf.MTE,NameLen, Name);
    return rc;
}
/*-------------------------------------*/
int main(int argc, char **argv)
{
   APIRET rc;
   PEXCEPTIONREPORTRECORD       pERepRec;
   PCONTEXTRECORD               pCtxRec;
   char  * Dot;
   char  * Slash;
   BOOL First;
   ULONG SessId;
   STARTDATA StartData;
   REQUESTDATA Request;
   ULONG       cbData;
   PUSHORT     Data;
   BYTE        priority;
   ULONG       cbEntries;
   ULONG       AppType;
   int i;
   if (argc==1) {
      printf("Program Name Missing\n");
      return ERROR_INVALID_PARAMETER;
   } /* endif */
   argc--;argv++;
   /*--------------------------------------------------*/
   /*- Check if watch points required -----------------*/
   while (argv[0][0]=='/') {
      if (WatchPointCount<4) {
          WatchPoint[WatchPointCount]=strtoul(argv[0]+1,&stopstring,16);
          WatchPointCount++;
      } else {
         printf("386 processor only supports a maximum of 4 watch points\n");
      } /* endif */
      argc--;argv++;
      if (argc==0) {
         break;
      } /* endif */
   } /* endwhile */
   /*--------------------------------------------------*/
   /*- Build new command line    ----------------------*/
   /* strcpy(CmdBuf,argv[0]); Only for DosExecPgm */
   strcpy(ProcessName,argv[0]);
   Dot=strrchr(ProcessName,'.');
   /*-- look for .EXE */
   if (Dot==NULL) {
      strcat(ProcessName,".EXE");
   } else {
      Slash=strrchr(ProcessName,'\\');
      /* Maybe '.' for current directory but no EXE extension */
      if (Slash>Dot) {
         strcat(ProcessName,".EXE");
      } /* endif */
   } /* endif */
   strupr(ProcessName);
   CmdPtr=CmdBuf/*+strlen(CmdBuf)+1*/;
   *CmdPtr=0x00; /* Add supplem */
   argc--;argv++;
   for (i=0;i<argc;i++ ) {
      strcat(CmdPtr," ");
      strcat(CmdPtr,argv[i]);
   } /* endfor */
   /*--------------------------------------------------*/
   printf("Execution results in PROCESS.TRP file\n");
   hTrap=fopen("PROCESS.TRP","w");
   setbuf( hTrap, NULL);
   /*--------------------------------------------------*/
// rc = DosExecPgm(LoadError,          /* Object name buffer */
//                 sizeof(LoadError),  /* Length of object name buffer */
//                 EXEC_TRACE,         /* Asynchronous/Trace flags */
//                 CmdBuf,            /* Argument string */
//                 NULL,               /* Environment string */
//                 &ReturnCodes,       /* Termination codes */
//                 ProcessName);           /* Program file name */
   rc=DosCreateQueue( &QueueHandle , QUE_FIFO,QueueName);
   fprintf(hTrap,"Create queue rc %d\n", rc);
   memset(&StartData,0x00,sizeof(STARTDATA));
   DosQueryAppType(ProcessName,&AppType);
   AppType=0x0003 & AppType;
   StartData.Length=sizeof(STARTDATA);         /* length of data structure    */
   StartData.Related=SSF_RELATED_CHILD;        /* 0 = independent session,    */
                                               /* 1 = child session           */
   StartData.FgBg=SSF_FGBG_FORE;               /* 0 = start in foreground,    */
                                               /* 1 = start in background     */
   StartData.TraceOpt=SSF_TRACEOPT_TRACEALL;   /* 0 = no trace, 1 = trace     */
   StartData.PgmTitle=ProcessName;             /* address of program title    */
   StartData.PgmName=ProcessName;              /* address of program name     */
   StartData.PgmInputs=CmdBuf;                 /* input arguments             */
   StartData.TermQ      =QueueName;            /*address of program queue name*/
   StartData.Environment=NULL;                 /* environment string          */
   StartData.InheritOpt=SSF_INHERTOPT_PARENT;  /* where are handles and       */
                                               /*  environment inherited from */
                                               /* 0 = inherit from shell ,    */
                                               /*     1 = inherit from caller */
   StartData.SessionType=AppType;              /* session type                */
   StartData.IconFile  =0;                     /* address of icon definition  */
   StartData.PgmHandle =0;                     /* program handle              */
   StartData.PgmControl=SSF_CONTROL_VISIBLE;   /*initial state of windowed app*/
   StartData.InitXPos=  0;                     /*x coor of init session window*/
   StartData.InitYPos=  0;                     /*y coor of init session window*/
   StartData.InitXSize= 0;                     /* initial size of x           */
   StartData.InitYSize= 0;                     /* initial size of y           */
   StartData.Reserved =0;
   StartData.ObjectBuffer=ObjectBuffer;
   StartData.ObjectBuffLen=sizeof(ObjectBuffer);
   DosSelectSession(0);
   rc=DosStartSession(
     &StartData,
     &SessId,
     &ReturnCodes.codeTerminate);
   fprintf(hTrap,"rc = %d Process ID %d  Session %d >%s<>%s<>%s<\n",
             rc,
             ReturnCodes.codeTerminate,
             SessId,ProcessName,ObjectBuffer,CmdBuf);
   if (rc != NO_ERROR) {
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
   for (i=0;i<WatchPointCount;i++) {
       fprintf(hTrap,"Addind watch point %8.8X\n",WatchPoint[i]);
       DbgBuf.Cmd = DBG_C_SetWatch;/* Indicate that a Connect is requested */
       DbgBuf.Pid = ReturnCodes.codeTerminate;
       DbgBuf.Tid = 0;
       DbgBuf.Addr   = WatchPoint[i];
       switch (WatchPoint[i]&0x00000003) {
          case 0:
             DbgBuf.Len    = 4; /* double word boundary */
          break;
          case 1:
             DbgBuf.Len    = 1; /* 1 byte boundary */
          break;
          case 2:
             DbgBuf.Len    = 2; /* word boundary */
          break;
          case 3:
             DbgBuf.Len    = 1; /* 1 byte boundary */
          break;
       } /* endswitch */
       DbgBuf.Value =  DBG_W_Write + DBG_W_Local;
       DbgBuf.Index =  0;
       rc = DosDebug(&DbgBuf);
       if (rc != 0) {
           fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
           fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
       } else {
         WatchIndex[i] =DbgBuf.Index;
      }
   } /* endfor */
   while (DbgBuf.Cmd!=DBG_N_ProcTerm) {
      DosSleep(50L);
      fprintf(hTrap,"Now Issuing Go\n");
      fflush(hTrap);
      DbgBuf.Cmd = DBG_C_Go; /* Indicate that a Connect is requested */
      DbgBuf.Pid = ReturnCodes.codeTerminate; /* Pid of Debuggee */
      rc = DosDebug(&DbgBuf);
      if (rc != 0) {
          fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
          fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
      }
      switch (DbgBuf.Cmd) {
          case DBG_N_SUCCESS:
             fprintf(hTrap,"DosDebug GO Successfull\n");
             break;
          case DBG_N_ERROR:
             fprintf(hTrap,"DosDebug Error %8.8lXx (%ld)\n",DbgBuf.Value,DbgBuf.Value);
             break;
          case DBG_N_ProcTerm:
             fprintf(hTrap,"Process Terminated with rc %d\n",DbgBuf.Value);
             break;
          case DBG_N_Exception:
             fprintf(hTrap,"Exception Occurred\n");
             break;
          case DBG_N_ModuleLoad:
             Name[0]=0x00;
             if (FirstLoaded==0) {
                FirstLoaded =(PLOADEDMODS)malloc(sizeof(LOADEDMODS));
                LastLoaded  = FirstLoaded;
             } else {
                LastLoaded->Next =(PLOADEDMODS)malloc(sizeof(LOADEDMODS));
                LastLoaded=LastLoaded->Next;
             }
             LastLoaded->Next=0;
             LastLoaded->hMte=DbgBuf.Value;
             rc=DosQueryModuleName(DbgBuf.Value,CCHMAXPATH, Name);
             fprintf(hTrap,"MODULE %s loaded\n",Name);
             break;
          case DBG_N_CoError:
             fprintf(hTrap,"Coprocessor Error\n");
             break;
          case DBG_N_ThreadTerm:
             fprintf(hTrap,"Thread %d Terminated with rc %d\n",DbgBuf.Tid,DbgBuf.Value);
             break;
          case DBG_N_AsyncStop:
             fprintf(hTrap,"Asynchronous Stop\n");
             break;
          case DBG_N_NewProc:
             fprintf(hTrap,"Debuggee started New Process Pid %X\n",DbgBuf.Value);
             break;
          case DBG_N_AliasFree:
             fprintf(hTrap,"Alias Freed\n");
             break;
          case DBG_N_Watchpoint:
             fprintf(hTrap,"WatchPoint Hit\n");
             for (i=0;i<WatchPointCount;i++) {
                if (WatchIndex[i] ==DbgBuf.Index) {
                   fprintf(hTrap,"Process %d\n",DbgBuf.Value);
                   fprintf(hTrap,"Thread %d\n",DbgBuf.Len);
                   fprintf(hTrap,"Wrote at address %8.8X\n",WatchPoint[i]);
                   fprintf(hTrap,"From instruction at address %8.8X\n",DbgBuf.Addr);
                   Name[0]=0x00;
                   rc=DosQueryModuleName(DbgBuf.MTE,CCHMAXPATH, Name);
                   if (rc==0) {
                      fprintf(hTrap,"In module %s\n",Name);
                      GetObjects(&DbgBuf,DbgBuf.MTE,Name);
                   } /* endif */
                   break;
                } /* endif */
             } /* endfor */
             break;
          case DBG_N_ThreadCreate:
             fprintf(hTrap,"Thread %d Created\n",DbgBuf.Tid);
             break;
          case DBG_N_ModuleFree:
             Name[0]=0x00;
             rc=DosQueryModuleName(DbgBuf.Value,CCHMAXPATH, Name);
             fprintf(hTrap,"MODULE %s freed\n",Name);
             break;
          case DBG_N_RangeStep:
             fprintf(hTrap,"RangeStep fault\n");
             break;
      } /* endswitch */
      fflush(hTrap);
      if (DbgBuf.Cmd==DBG_N_Exception) {
            if ((DbgBuf.Value==DBG_X_FIRST_CHANCE) ||
                (DbgBuf.Value==DBG_X_STACK_INVALID)) {
                fprintf(hTrap,"Got the exception on Thread %d\n",DbgBuf.Tid);
                pERepRec=(PEXCEPTIONREPORTRECORD)DbgBuf.Buffer;
                pCtxRec =(PCONTEXTRECORD)DbgBuf.Len;
                if (CheckExcep(pERepRec,pCtxRec)) break;
            }
      } /* endif */
   } /* endwhile */
  // fclose(hTrap);
}
static ULONG  Version[2];
APIRET CheckExcep( PEXCEPTIONREPORTRECORD       pERepRec,
                   PCONTEXTRECORD               pCtxRec) {
  APIRET rc;
  USHORT Count;
  USHORT Passes;
  UCHAR   CodeCopy[80];
  UCHAR   Translate[17];
  UCHAR   OldStuff[16];
  PUSHORT StackPtr;
  PUCHAR  cStackPtr;
  EXCEPTIONREPORTRECORD       ERepRec;
  CONTEXTRECORD               CtxRec;
  static CHAR Format[10];
  ULONG  stacklen;
  UCHAR *stackptr;
  HMODULE hMod;
  fprintf(hTrap,"\n/*----- getting exception records ---*/\n");
  DbgBuf.Cmd = DBG_C_ReadMemBuf; /* Indicate that a Connect is requested */
  DbgBuf.Pid = ReturnCodes.codeTerminate; /* Pid of Debuggee */
  DbgBuf.Addr   =(ULONG) pERepRec;
  DbgBuf.Buffer =(ULONG) &ERepRec;
  DbgBuf.Len    = sizeof(EXCEPTIONREPORTRECORD);
  rc = DosDebug(&DbgBuf);
  if (rc != 0) {
      fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
      fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
      return 1;
  }
  fprintf(hTrap,"\n/*----- getting Context record ---*/\n");
  DbgBuf.Cmd = DBG_C_ReadMemBuf; /* Indicate that a Connect is requested */
  DbgBuf.Pid = ReturnCodes.codeTerminate; /* Pid of Debuggee */
  DbgBuf.Addr   =(ULONG) pCtxRec;
  DbgBuf.Buffer =(ULONG) &CtxRec;
  DbgBuf.Len    = sizeof(CONTEXTRECORD);
  rc = DosDebug(&DbgBuf);
  if (rc != 0) {
      fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
      fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
      return 1;
  }
  if ((ERepRec.ExceptionNum&XCPT_SEVERITY_CODE)==XCPT_FATAL_EXCEPTION)
  {
    if ((ERepRec.ExceptionNum!=XCPT_PROCESS_TERMINATE)&&
        (ERepRec.ExceptionNum!=XCPT_UNWIND)&&
        (ERepRec.ExceptionNum!=XCPT_SIGNAL)&&
        (ERepRec.ExceptionNum!=XCPT_ASYNC_PROCESS_TERMINATE)) {
        fprintf(hTrap,"--------------------------\n");
        fprintf(hTrap,"Exception %8.8lX Occurred\n",ERepRec.ExceptionNum);
        fprintf(hTrap," at %s ",_strtime(Buffer));
        fprintf(hTrap," %s\n",_strdate(Buffer));
        if ( ERepRec.ExceptionNum     ==         XCPT_ACCESS_VIOLATION)
        {
           switch (ERepRec.ExceptionInfo[0]) {
                case XCPT_READ_ACCESS:
                case XCPT_WRITE_ACCESS:
                   fprintf(hTrap,"Invalid linear address %8.8lX\n",ERepRec.ExceptionInfo[1]);
                   break;
                case XCPT_SPACE_ACCESS:
                  /* Thanks to John Currier              */
                  /* It looks like this is off by one... */
                  fprintf(hTrap,"Invalid Selector: %8.8p",
                                 ERepRec.ExceptionInfo[1] ?
                                 ERepRec.ExceptionInfo[1] + 1 : 0);
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
        DbgBuf.Addr   =(ULONG) ERepRec.ExceptionAddress;
        DbgBuf.Cmd = DBG_C_AddrToObject;/* Indicate that a AddrToObject is requested */
        DbgBuf.Pid = ReturnCodes.codeTerminate; /* Pid of Debuggee */
        rc = DosDebug(&DbgBuf);
        if ((rc==0)&&(DbgBuf.Value&DBG_O_OBJMTE)) {
          rc=DosQueryModuleName(DbgBuf.MTE,CCHMAXPATH, Name);
          fprintf(hTrap,"Failing code module file name : %s\n",Name);
          fprintf(hTrap,"Failing Object starting at %x,failure at Offset %x \n",DbgBuf.Buffer,DbgBuf.Addr-DbgBuf.Buffer);
        } /* endif */
        fprintf(hTrap,"ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿\n");
        if ( (CtxRec.ContextFlags) & CONTEXT_SEGMENTS ) {
             fprintf(hTrap,"³ GS  : %4.4lX     ",CtxRec.ctx_SegGs);
             fprintf(hTrap,"FS  : %4.4lX     ",CtxRec.ctx_SegFs);
             fprintf(hTrap,"ES  : %4.4lX     ",CtxRec.ctx_SegEs);
             fprintf(hTrap,"DS  : %4.4lX     ³\n",CtxRec.ctx_SegDs);
        } /* endif */
        if ( (CtxRec.ContextFlags) & CONTEXT_INTEGER  ) {
             fprintf(hTrap,"³ EDI : %8.8lX ",CtxRec.ctx_RegEdi  );
             fprintf(hTrap,"ESI : %8.8lX ",CtxRec.ctx_RegEsi  );
             fprintf(hTrap,"EAX : %8.8lX ",CtxRec.ctx_RegEax  );
             fprintf(hTrap,"EBX : %8.8lX ³\n",CtxRec.ctx_RegEbx  );
             fprintf(hTrap,"³ ECX : %8.8lX ",CtxRec.ctx_RegEcx  );
             fprintf(hTrap,"EDX : %8.8lX                               ³\n",CtxRec.ctx_RegEdx  );
        } /* endif */
        if ( (CtxRec.ContextFlags) & CONTEXT_CONTROL  ) {
             void * _Seg16 Ptr16;
             fprintf(hTrap,"³ EBP : %8.8lX ",CtxRec.ctx_RegEbp  );
             fprintf(hTrap,"EIP : %8.8lX ",CtxRec.ctx_RegEip  );
             fprintf(hTrap,"EFLG: %8.8lX ",CtxRec.ctx_EFlags  );
             fprintf(hTrap,"ESP : %8.8lX ³\n",CtxRec.ctx_RegEsp  );
             fprintf(hTrap,"³ CS  : %4.4lX     ",CtxRec.ctx_SegCs   );
             fprintf(hTrap,"SS  : %4.4lX                                   ³",CtxRec.ctx_SegSs   );
             fprintf(hTrap,"\n³ CSLIM: %8.8lX ",DbgBuf.CSLim);
             fprintf(hTrap,"SSLIM: %8.8lX                             ³",DbgBuf.SSLim);
             fprintf(hTrap,"\nÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ\n");
             /*
             fprintf(hTrap,"FSLIM: %8.8lX \n",DbgBuf.FSLim);
             fprintf(hTrap,"FSBase: %8.8lX \n",DbgBuf.FSBase);
             fprintf(hTrap,"FS    : %4.4X \n",DbgBuf.FS);
             */
             f32bit=BigSeg=((CtxRec.ctx_RegEip)>0x00010000);
             if (DbgBuf.CSLim-sizeof(CodeCopy[80])>CtxRec.ctx_RegEip) {
                if (CtxRec.ctx_RegEip<0x10000) { /* code  is 16:16 */
                   DbgBuf.Cmd   = DBG_C_SelToLin;
                   DbgBuf.Pid   = ReturnCodes.codeTerminate; /* Pid of Debuggee */
                   DbgBuf.Value = CtxRec.ctx_SegCs;
                   DbgBuf.Index = CtxRec.ctx_RegEip;
                   rc = DosDebug(&DbgBuf);
                   if (rc != 0) {
                       fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
                       fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
                       return 1;
                   }
                   fprintf(hTrap,"Linear 16:16 stack Address %p\n",DbgBuf.Addr);
                   CodeAddress=DbgBuf.Addr;
                } else {
                   CodeAddress  =(ULONG) CtxRec.ctx_RegEip;
                } /* endif */
                DbgBuf.Cmd = DBG_C_AddrToObject;/* Indicate that a AddrToObject is requested */
                DbgBuf.Pid = ReturnCodes.codeTerminate; /* Pid of Debuggee */
                rc = DosDebug(&DbgBuf);
                if (rc != 0) {
                    fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
                    fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
                    return 1;
                }
                rc=DbgQueryModFromEIP( &hMod, &ObjNum, CCHMAXPATH,
                                Name, &Offset, ERepRec.ExceptionAddress);

                if (rc==NO_ERROR) {
                   fprintf(hTrap,"Failing code module file name : %s\n",Name);
                   fprintf(hTrap,"Failing code Object # %d at Offset %x \n",ObjNum+1,Offset);
                   if (strlen(Name)>3) {
                      fprintf(hTrap,"      File     Line#  Public Symbol\n");
                      fprintf(hTrap,"  ÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄ-  ÄÄÄÄÄÄÄÄÄÄÄÄ-\n");
                      rc =GetLineNum(Name,ObjNum,Offset);


                      /* if no codeview try with symbol files */
                      if (rc!=0) {
                         strcpy(Name+strlen(Name)-3,"SYM"); /* Get Sym File name */
                         GetSymbol(Name,ObjNum,Offset);
                      } /* endif */
                   } /* endif */
                   fprintf(hTrap,"\n");
                } /* endif */
                DbgBuf.Cmd  = DBG_C_ReadMemBuf; /* Indicate that a Connect is requested */
                DbgBuf.Pid  = ReturnCodes.codeTerminate; /* Pid of Debuggee */
                DbgBuf.Addr = CodeAddress;
                DbgBuf.Len  = sizeof(CodeCopy);
                DbgBuf.Buffer =(ULONG) CodeCopy;
                rc = DosDebug(&DbgBuf);
                if (rc != 0) {
                    fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
                    fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
                } else {
                    AsmLine= DISASM( (PVOID) CodeCopy,
                                  (USHORT)CodeCopy, BigSeg );
                    fprintf(hTrap,"\n Failing instruction at CS:EIP : %4.4X:%8.8X is  %s\n\n",
                         CtxRec.ctx_SegCs,
                         CtxRec.ctx_RegEip,AsmLine->buf);
                }
             }
             ListModules();
             /*------ Now the stack ---------------------------*/
             /*--I should use the stacklimits in the struture--*/
             /*--pointed by FS:0 but there is a bug in OS/2  --*/
             /*--see APAR PJ06136 FS is mapped to the        --*/
             /*--debuggers thread not the debuggee  !!!!!!   --*/
             fprintf(hTrap,"\n/*----- getting Stack Object ---*/\n");
             if (CtxRec.ctx_RegEsp<0x10000) { /* stack is 16:16 */
                DbgBuf.Cmd   = DBG_C_SelToLin;
                DbgBuf.Pid   = ReturnCodes.codeTerminate; /* Pid of Debuggee */
                DbgBuf.Value = CtxRec.ctx_SegSs;
                DbgBuf.Index = CtxRec.ctx_RegEsp;
                rc = DosDebug(&DbgBuf);
                if (rc != 0) {
                    fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
                    fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
                    return 1;
                }
                fprintf(hTrap,"Linear 16:16 stack Address %p\n",DbgBuf.Addr);
             } else {
                DbgBuf.Addr   =(ULONG) CtxRec.ctx_RegEsp;
             } /* endif */
             DbgBuf.Cmd = DBG_C_AddrToObject;/* Indicate that a AddrToObject is requested */
             DbgBuf.Pid = ReturnCodes.codeTerminate; /* Pid of Debuggee */
             rc = DosDebug(&DbgBuf);
             if (rc != 0) {
                 fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
                 fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
                 return 1;
             }
             stacklen   = DbgBuf.Len;
             fprintf(hTrap,"Thread  Id %lu \n", DbgBuf.Tid);
             Ptr16=(void * _Seg16)DbgBuf.Buffer;
             sprintf(Format,"%8.8lX",Ptr16);
             fprintf(hTrap,"Stack Bottom : %8.8lX (%4.4s:%4.4s) ;",DbgBuf.Buffer,Format,Format+4);
             Ptr16=(void * _Seg16)(DbgBuf.Buffer+DbgBuf.Len-1);
             sprintf(Format,"%8.8lX",Ptr16);
             fprintf(hTrap,"Stack Top    : %8.8lX (%4.4s:%4.4s) \n",DbgBuf.Buffer+DbgBuf.Len,Format,Format+4);
             fprintf(hTrap,"Process Id : %lu ", DbgBuf.Pid);
             StackBase=(PUSHORT)DbgBuf.Buffer;
             Count=0;
             Translate[0]=0x00;
             StackCopy=malloc(stacklen);
             fprintf(hTrap,"\n/*----- Stack Object Bottom -<%8.8X>--*/\n",DbgBuf.Buffer);
             fprintf(hTrap,"StackCopy %p Length %d\n\n", StackCopy,DbgBuf.Len);
             DbgBuf.Cmd  = DBG_C_ReadMemBuf; /* Indicate that a Connect is requested */
             DbgBuf.Pid  = ReturnCodes.codeTerminate; /* Pid of Debuggee */
             DbgBuf.Addr = DbgBuf.Buffer;
             DbgBuf.Len  = stacklen;
             DbgBuf.Buffer =(ULONG) StackCopy;
             rc = DosDebug(&DbgBuf);
             if (rc != 0) {
                 fprintf(hTrap,"DosDebug error: return code = %ld Note %8.8lX\n", rc,DbgBuf.Cmd);
                 fprintf(hTrap,"Value          = %8.8lX %ld\n",DbgBuf.Value,DbgBuf.Value);
             } else {
                 /* Better New WalkStack From John Currier */
                 WalkStack((PUSHORT)StackCopy,
                           (PUSHORT)(StackCopy+stacklen),
                           (PUSHORT)CtxRec.ctx_RegEbp,
                           (PUSHORT)ERepRec.ExceptionAddress);
                 memset(OldStuff,0,16);
                 for (StackPtr=(PUSHORT)StackCopy;
                      StackPtr<(PUSHORT)(StackCopy+stacklen);
                      StackPtr++) {

                      if (Count==0) {
                         if (memcmp(OldStuff,StackPtr,16)){
                             memcpy(OldStuff,StackPtr,16);
                             Passes = 0;
                         } else {
                             if (Passes == 0) {
                                 Passes = 1;
                                 fprintf(hTrap," Same as above.\n");
                             }
                             StackPtr+= 7;
                             continue;
                         }
                      }
                      if (Count==0) {
                         fprintf(hTrap," %8.8X :",StackBase+(((PUCHAR)StackPtr)-StackCopy));
                      } /* endif */
                      fprintf(hTrap,"%4.4hX ",*StackPtr);
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
                         fprintf(hTrap,"  %s\n",Translate);
                         Translate[0]=0x00;
                      } /* endif */
                 } /* endfor */
                 fprintf(hTrap,"  %s\n/*----- Stack Object Top -<%8.8X>----*/\n",Translate
                                  ,DbgBuf.Addr+(((PUCHAR)StackPtr)-StackCopy));
             } /* endif */
        } /* endif */
     } else {
        fprintf(hTrap,"Other fatal exception %8.8lx ",ERepRec.ExceptionNum);
        fprintf(hTrap,"At address            %8.8lx\n",ERepRec.ExceptionAddress);
     } /* endif */
     return 1L;
  } else {
     fprintf(hTrap,"Other non fatal exception %8.8lx ",ERepRec.ExceptionNum);
     fprintf(hTrap,"At address                %8.8lx\n",ERepRec.ExceptionAddress);
     return 0L;
  } /* endif */

}
VOID ListModules() {
  APIRET   rc;
  APIRET16 rc16;
#if USE_DOSQPROC
  /**----------------------------------***/
  rc16=DOS16ALLOCSEG( 0xFFFF , &Selector , 0);
  if (rc16==0) {
     pBuf=MAKEP(Selector,0);
     rc16=DOSQPROCSTATUS(pBuf, 0xFFFF );
     if (rc16==0) {
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
#endif
  /* Limit object dump to the loaded modules of the debuggee only */
  LastLoaded=FirstLoaded;
  while (LastLoaded!=0) {
      rc=DosQueryModuleName(LastLoaded->hMte,CCHMAXPATH, Name);
      GetObjects(&DbgBuf,LastLoaded->hMte,Name);
      LastLoaded=LastLoaded->Next;
  } /* endwhile */
}
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
                if (rc != NO_ERROR) {
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
   PUSHORT  LocalEbp; /* Ebp on local Stack copy */
   BOOL     fExceptionAddress = TRUE;  // Use Exception Addr 1st time thru

   fprintf(hTrap,"\nEBP on Entry=%8.8X Exception Address %8.8X\n",Ebp,ExceptionAddress);
   // Note: we can't handle stacks bigger than 64K for now...
   Sp = (USHORT)(((ULONG)StackBase) >> 16);
   Bp = (USHORT)(ULONG)Ebp;

   if (!f32bit)
      Ebp = (PUSHORT)MAKEULONG(Bp, Sp);

   fprintf(hTrap,"\nCall Stack:\n");
   fprintf(hTrap,"                                        Source    Line      Nearest\n");
   fprintf(hTrap,"   EBP      Address    Module  Obj#      File     Numbr  Public Symbol\n");
   fprintf(hTrap," ÄÄÄÄÄÄÄÄ  ÄÄÄÄÄÄÄÄÄ  ÄÄÄÄÄÄÄÄ ÄÄÄÄ  ÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄ-  ÄÄÄÄÄÄÄÄÄÄÄÄ-\n");

   do
   {
      Size = 10;
      LocalEbp=StackBottom+(Ebp-StackBase);
      rc = DosQueryMem((PVOID)(LocalEbp+2), &Size, &Attr);
      if (rc != NO_ERROR || !(Attr & PAG_COMMIT) ||  (Size<10) )
      {
         fprintf(hTrap,"Invalid EBP: %8.8p\n",Ebp);
         break;
      }

      if (fExceptionAddress)
         RetAddr = ExceptionAddress;
      else
         RetAddr = (PUSHORT)(*((PULONG)(LocalEbp+2)));

      if (RetAddr == (PUSHORT)0x00000053)
      {
         // For some reason there's a "return address" of 0x53 following
         // EBP on the stack and we have to adjust EBP by 44 bytes to get
         // at the real return address.  This has something to do with
         // thunking from 32bits to 16bits...
         // Serious kludge, and it's probably dependent on versions of C(++)
         // runtime or OS, but it works for now!
         Ebp += 22;
         RetAddr = (PUSHORT)(*((PULONG)(LocalEbp+2)));
      }

      // Get the (possibly) 16bit CS and IP
      if (fExceptionAddress)
      {
         Cs = (USHORT)(((ULONG)ExceptionAddress) >> 16);
         Ip = (USHORT)(ULONG)ExceptionAddress;
      }
      else
      {
         Cs = *(LocalEbp+2);
         Ip = *(LocalEbp+1);
      }

      // if the return address points to the stack then it's really just
      // a pointer to the return address (UGH!).
      if ((USHORT)(((ULONG)RetAddr) >> 16) == Sp)
         RetAddr = (PUSHORT)(*((PULONG)RetAddr));

      if (Ip == 0 && *LocalEbp == 0)
      {
         // End of the stack so these are both shifted by 2 bytes:
         Cs = *(LocalEbp+3);
         Ip = *(LocalEbp+2);
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
      if (!fExceptionAddress) {
         if (Ip != Sp)
         {
            DbgBuf.Cmd   = DBG_C_SelToLin;
            DbgBuf.Pid   = ReturnCodes.codeTerminate; /* Pid of Debuggee */
            DbgBuf.Value = Cs;
            DbgBuf.Index = Ip;
            rc = DosDebug(&DbgBuf);
            if (rc != 0) {
               DbgBuf.Cmd   = DBG_C_SelToLin;
               DbgBuf.Pid   = ReturnCodes.codeTerminate; /* Pid of Debuggee */
               DbgBuf.Value = (Cs << 3) + 7;
               DbgBuf.Index = Ip;
               rc = DosDebug(&DbgBuf);
               if (rc != 0) {
                   f32bit = TRUE;
               } else {
                  Cs = (Cs << 3) + 7;
                  RetAddr = (USHORT * _Seg16)MAKEULONG(Ip, Cs);
                  f32bit = FALSE;
               }
            } else {
               RetAddr = (USHORT * _Seg16)MAKEULONG(Ip, Cs);
               f32bit = FALSE;
            }
         }
         else
            f32bit = TRUE;
      }


      if (fExceptionAddress)
         fprintf(hTrap," Trap  ->");
      else
         fprintf(hTrap," %8.8p", Ebp);

      if (f32bit)
         fprintf(hTrap,"  :%8.8p", RetAddr);
      else
         fprintf(hTrap,"  %04.04X:%04.04X", Cs, Ip);

      // Make a 'tick' sound to let the user know we're still alive
      DosBeep(2000, 1);
      rc= DbgQueryModFromEIP(&hMod, &ObjNum, sizeof(Name),
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
      } else {
         fprintf(hTrap,"rc %d Objnum %d",rc,ObjNum);
      }



      fprintf(hTrap,"\n");
      if (fExceptionAddress) {
          LocalEbp=StackBottom+(Ebp-StackBase);
          print_vars((ULONG)LocalEbp);
      }

      LocalEbp=StackBottom+(Ebp-StackBase);
      Bp = *LocalEbp;
      if (Bp == 0 && (*LocalEbp+1) == 0)
      {
         fprintf(hTrap,"End of Call Stack\n");
         break;
      }

      if (!fExceptionAddress)
      {
         LastEbp = Ebp;
         Ebp = (PUSHORT)MAKEULONG(Bp, Sp);
         if (f32bit) {
             LocalEbp=StackBottom+(Ebp-StackBase);
             print_vars((ULONG)LocalEbp);
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
      LocalEbp=StackBottom+(Ebp-StackBase);
      rc = DosQueryMem((PVOID)LocalEbp, &Size, &Attr);
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
   static unsigned short int SegOffset,SymOffset,SymPtrOffset;
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
   unsigned short FileNum;
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
   var_ofs = 0;
   strcpy(func_name,"Unknown function name");
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
int Read32PmDebug(int fh,int TrapSeg,int TrapOff,CHAR * FileName) {
    static unsigned int CurrSymSeg, NrSymbol,offset,NrPublic,NrFile,NrLine,NrEntry,numdir,namelen,numlines,line;
    static int ModIndex;
    static int bytesread,i,j;
    static int pOffset;
    static SSLINEENTRY32 LineEntry;
    static SSFILENUM32 FileInfo;
    static FIRSTLINEENTRY32 FirstLine;
    static BYTE dump_vars = FALSE;

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
                       sprintf(szNrPub,"%s %s (%s) %04X:%08X\n",
                               (sspub32.type==1) ? " Abs" : " ",ename,ModName,
                               sspub32.segment, sspub32.offset
                               );
                   }
               }
               break;

            /* Read symbols, so we can dump the variables on the stack */
            case SSTSYMBOLS:
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
#if 0
                           sprintf(func_name, "Function, Start offset: %08X, Type: %04X, Name: \"%s\"\n",
                                   symproc.offset, symproc.type_idx, str);
#else
                           strcpy(func_name, str);
#endif
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
#if 0
                        if (symauto.type_idx >= 0x80 && symauto.type_idx <= 0xDA)
                           sprintf(var_name[var_ofs], "Auto var, Offset: %08X, Type: %s, Name: \"%s\"\n", symauto.stack_offset,
                            type_name[symauto.type_idx-0x80], str);
                        else
                           sprintf(var_name[var_ofs], "Auto var, Offset: %08X, Type: %04X, Name: \"%s\"\n",
                                  symauto.stack_offset, symauto.type_idx, str);
#endif
                        var_ofs++;
                        break;

                  }

                  bytesread += usLength;

                  lseek(fh, ofs+usLength, SEEK_SET);
               }
               break;


            case SSTSRCLINES32:
               if (TrapSeg!=ssmod32.csBase) break;
               /* read first line */
               read(fh,(void *)&FirstLine,sizeof(FirstLine));
               if (FirstLine.LineNum!=0) {
                  fprintf(hTrap,"Missing Line table information\n");
                  break;
               } /* endif */
               numlines= FirstLine.numlines;
               /* Other type of data skip 4 more bytes */
               if (FirstLine.segnum!=0) {
                  lseek(fh,4,SEEK_CUR);
               }
               for (j=0;j<numlines;j++) {
                  read(fh,(void *)&LineEntry,sizeof(LineEntry));
                  if (LineEntry.Offset+ssmod32.csOff<=TrapOff && LineEntry.Offset+ssmod32.csOff>=NrLine) {
                     NrLine=LineEntry.Offset;
                     NrFile=LineEntry.FileNum;
                     /*pOffset =sprintf(szNrLine,"%04X:%08X  line #%hu ",
                             ssmod32.csBase,LineEntry.Offset,
                             LineEntry.LineNum);*/
                    sprintf(szNrLine,"% 6hu", LineEntry.LineNum);
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
         sprintf(value, "%p invalid", *(ULONG *)varptr);
      } else {
         sprintf(value, "%p", *(ULONG *)varptr);
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

void print_vars(ULONG stackofs)
{
   USHORT n;
   BOOL   AutoVarsFound=FALSE;

/*   stackofs += stack_ebp; */
   if (func_ofs == pubfunc_ofs) {
      for(n = 0; n < var_ofs; n++) {
         if (autovar_def[n].type_idx >= 0x80 && autovar_def[n].type_idx <= 0xDA)
         {
            if (AutoVarsFound==FALSE) {
                AutoVarsFound=TRUE;
                fprintf(hTrap, "List of auto variables at EBP %p in %s:\n",stackofs, func_name);
                fprintf(hTrap,"Offset Name                 Type                              Value            \n");
                fprintf(hTrap,"ÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ\n");
            }
            fprintf(hTrap, "%- 6d %- 20.20s %s %s\n",
                    autovar_def[n].stack_offset,
                    autovar_def[n].name,
                    type_name[autovar_def[n].type_idx-0x80],
                    var_value((void *)(stackofs+autovar_def[n].stack_offset),
                              autovar_def[n].type_idx-0x80));
         }
         else {
            if (AutoVarsFound==FALSE) {
                AutoVarsFound=TRUE;
                fprintf(hTrap, "  List of auto variables in %s:\n", func_name);
                fprintf(hTrap,"Offset Name                 Type                              Value            \n");
                fprintf(hTrap,"ÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ\n");
            }
            fprintf(hTrap, "%- 6d %-20.20s %u\n",
                           autovar_def[n].stack_offset,
                           autovar_def[n].name,
                           autovar_def[n].type_idx);
         }
      }
      if (AutoVarsFound==FALSE) {
          fprintf(hTrap, "  No auto variables found in %s.\n", func_name);
      }
      fprintf(hTrap, "\n");
   }
}
