
/* $Id: WatcomSample.c,v 1.2 2004/07/30 04:28:40 root Exp $
  This is a bit of incomplete code to demonstrate how allow EXCEPTQ
  to work with Watcom.  I haven't yet figured out how to allow it to
  successfully read the codeview information that Watcom writes.

  Ed Becker / Sauron@mymail.com

*/

#define INCL_DOSEXCEPTIONS
#include <os2.h>

#include <sys/ioctl.h>			// for FIONBIO used in nonblock()
#include <fcntl.h>

LONG _cdecl ExceptionHandler(PEXCEPTIONREPORTRECORD pERepRec,
			     PEXCEPTIONREGISTRATIONRECORD pERegRec,
			     PCONTEXTRECORD pCtxRec,
			     PVOID pv);

typedef struct SysERegRec {
	PEXCEPTIONREGISTRATIONRECORD pLink;
	ULONG (_cdecl *pSysEH)(PEXCEPTIONREPORTRECORD,
			      PEXCEPTIONREGISTRATIONRECORD,
			      PCONTEXTRECORD,
			      PVOID);
} SYSEREGREC;

extern ULONG APIENTRY myHandler(PEXCEPTIONREPORTRECORD       pERepRec,
				PEXCEPTIONREGISTRATIONRECORD pERegRec,
				PCONTEXTRECORD               pCtxRec,
				PVOID                        p);


main(int argc, char *argv[], char *envp[])
{
  SYSEREGREC  RegRec;

  RegRec.pLink = 0;
  RegRec.pSysEH = (ULONG _cdecl) myHandler;

   // To register the handler
   // EXCEPTIONREGISTRATIONRECORD er = { NULL,  ExceptionHandler };

   rc = DosSetExceptionHandler((PEXCEPTIONREGISTRATIONRECORD)&RegRec);

} // main

// The end
