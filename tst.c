#include <stdio.h>
#define INCL_DOS
#include <os2.h>
PVOID   _System _DosSelToFlat(ULONG SelAdd);
main() {
   PVOID Address=NULL;
   ULONG In=0x150B0000;
   Address = _DosSelToFlat(In);
   printf("Address =%p\n",Address);

}
