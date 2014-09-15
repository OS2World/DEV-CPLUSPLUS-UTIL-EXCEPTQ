/**********************************************************************/
/**********************************************************************/
/*                                                                    */
/*  TRAPPERQ                                                          */
/*                                                                    */
/* Program demonstration EXCEPTQ.DLL usage                            */
/* TrapperQ is preferable to Trapper which uses EXCEPT.DLL            */
/* Compiled with IBM C/2 see SAMPLE.C for 32 bit C-SET/2 sample       */
/**********************************************************************/
/* Version: 2.2             |   Marc Fiammante (FIAMMANT at LGEVM2)   */
/**********************************************************************/
/*                                                                    */
/**********************************************************************/
/* History:                                                           */
/* --------                                                           */
/*                                                                    */
/* created: Marc Fiammante December 1992                              */
/**********************************************************************/
#include <mt\stdio.h>
#include <mt\conio.h>
#include <mt\process.h>
#define INCL_BASE
#include <os2.h>
USHORT rc;
PCHAR  Test;
struct _EXCEPTIONREGISTRATIONRECORD
   {
      struct _EXCEPTIONREGISTRATIONRECORD * prev_structure;
      PFN Handler;
   };
typedef struct _EXCEPTIONREGISTRATIONRECORD EXCEPTIONREGISTRATIONRECORD;
typedef struct _EXCEPTIONREGISTRATIONRECORD * PEXCEPTIONREGISTRATIONRECORD;
USHORT EXPENTRY SETEXCEPT(PEXCEPTIONREGISTRATIONRECORD);
USHORT EXPENTRY UNSETEXCEPT(PEXCEPTIONREGISTRATIONRECORD);
TID Tid;
#define STACKSIZE 0x2000
SEL   SelStack;
PCHAR StackPtr;
void   Thread(unsigned far *args);         /* Playing   thread function   */
void cdecl main() {
    EXCEPTIONREGISTRATIONRECORD ExceptReg;
    printf("Setting exception handler\n");
    rc=SETEXCEPT(&ExceptReg);
    DosAllocSeg(STACKSIZE,&SelStack,1);
    StackPtr=MAKEP(SelStack,0);
    Tid=_beginthread(
       Thread,
       (VOID FAR *)StackPtr,
       STACKSIZE,
       NULL);
      getch();
    rc=UNSETEXCEPT(&ExceptReg);
}
void TrapFct(PCHAR Parm) { /* Demonstrates stack walk */
    PCHAR  Test;
    printf("Generating the TRAP from thread\n");
    Test=Parm;
    *Test=0;
}
void   Thread(unsigned far *args) {
    EXCEPTIONREGISTRATIONRECORD ExceptReg;
    printf("Setting exception handler from the thread\n");
    rc=SETEXCEPT(&ExceptReg);
    TrapFct(NULL);
    rc=UNSETEXCEPT(&ExceptReg);
}
