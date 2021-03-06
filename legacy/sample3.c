/**********************************************************************
  sample3.c - test exceptq.dll using dynaminc loading and 16-bit code
  $Id: $

 SAMPLE 32 bit program to access EXCEPTQ.DLL exception handler via
 dynamically loaded DLL
 generates a TRAP in 16-bit code

 08 Aug 05 SHL Baseline

**********************************************************************/

#define INCL_DOSERRORS
#define INCL_DOSEXCEPTIONS
#define INCL_DOSMODULEMGR
#include <os2.h>

#include <stdio.h>
#include <stdlib.h>

void _Far16 TrapFunc(void);

main()
{
    _ERR *pfnMyHandler;
    EXCEPTIONREGISTRATIONRECORD excpQReg = { NULL, NULL };
    APIRET rc;
    HMODULE hmod = NULLHANDLE;
    char szLoadError[CCHMAXPATH];

    /* Dynamically load exceptq.dll if available */
    rc = DosLoadModule(szLoadError, CCHMAXPATH, "EXCEPTQ", &hmod);
    if (rc != NO_ERROR) {
	printf("EXCEPTQ.DLL not loaded.\n");
    } else {
	printf("EXCEPTQ.DLL loaded.\n");
	rc = DosQueryProcAddr(hmod, 0L, "MYHANDLER", (PFN*)&pfnMyHandler);
	if (rc != NO_ERROR) {
	    printf("MyHandler not found in EXCEPTQ.DLL.\n");
	    DosFreeModule(hmod);
	} else {
	    printf("MyHandler queried from EXCEPTQ.DLL.\n");
	    /* Add MyHandler to this thread's chain of exception handlers */
	    excpQReg.ExceptionHandler = pfnMyHandler;
	    rc = DosSetExceptionHandler(&excpQReg);
	    if (rc != NO_ERROR) {
	       printf("MyHandler not installed.\n");
	       DosFreeModule(hmod);
	    }
	}
    }

    TrapFunc();

    if (rc == NO_ERROR) {
	rc = DosUnsetExceptionHandler(&excpQReg);
	if (rc != NO_ERROR) {
	    printf("MyHandler could not be uninstalled\n");
	    exit(1);
	} else {
	    printf("MyHandler unset.\n");
	}
	DosFreeModule(hmod);
    }

    exit(0);
}

void _Far16 TrapFunc() {
    char * Test;
    Test=0;
    *Test=0;
}
