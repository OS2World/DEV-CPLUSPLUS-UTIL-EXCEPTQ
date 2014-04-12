/**********************************************************************/
/*                                                                    */
/*  SSS                                                               */

#include <conio.h>
#include <stdio.h>
#include <stdlib.h>

void TrapFunc(void);
#define INCL_BASE
#define INCL_DOSPROCESS
#define INCL_DOSSEMAPHORES   /* Semaphore values */
#include <os2.h>


void KeyboardThread(PVOID args) {
    printf("Keyboard read thread\n");
    getch();
    printf("Keyboard read\n");
}
void SemWaitThread(PVOID args) {
    HEV  WaitSem= 0;
    ULONG Count;
    DosCreateEventSem(0,&WaitSem,0,FALSE);
    DosResetEventSem(WaitSem,&Count);
    printf("Wait semaphore thread\n");
    DosWaitEventSem(WaitSem,SEM_INDEFINITE_WAIT);
    printf("Wait semaphore ended\n");
}
void QueueThread(PVOID args) {
    HQUEUE hq;
    REQUESTDATA Request;
    ULONG cbData;
    PVOID pbuf;
    APIRET rc;
    BYTE priority;
    rc=DosCreateQueue( &hq,QUE_FIFO,"\\QUEUES\\TESTEXIT");
    printf("Queue Created rc=%d\n",rc);
    printf("Now reading queue\n");
    rc=DosReadQueue(hq,&Request, &cbData, &pbuf,0,DCWW_WAIT,
                                    &priority, 0);
    printf("queue read\n");
}
void SleepingThread(PVOID args) {
    printf("Thread Sleeping\n");
    DosSleep(100000L);
}
VOID  APIENTRY  ForceExit(VOID);
main()
{
    _beginthread( SleepingThread,NULL, 4192,NULL );
    _beginthread( QueueThread   ,NULL, 4192,NULL );
    _beginthread( SemWaitThread ,NULL, 4192,NULL );
    _beginthread( KeyboardThread,NULL, 4192,NULL );
    printf("Waiting 2 seconds in thread 1\n");
    DosSleep(2000L);
    printf("Before ForceExit\n");
    ForceExit();
    printf("After ForceExit\n");  /* Should never be displayed */
}
