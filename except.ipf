.*--------------------------------------------------------------------
.* This file contains the tagged source for EXCEPT Package
.* $Id: except.ipf,v 1.2 2008/05/24 23:25:28 Steven Exp $
.*
.* 23 May 08 SHL Restore control area
.*--------------------------------------------------------------------

:userdoc.

.*--------------------------------------------------------------------
.* Provide a title for the title line of the main window
.*--------------------------------------------------------------------

:title.Except Package

.*--------------------------------------------------------------------
.* Allow only heading level 1 to appear in the contents window and
.* specify no control area for pushbuttons
.*--------------------------------------------------------------------

.* :docprof toc=1 ctrlarea=none.
:docprof toc=1

.*--------------------------------------------------------------------
.* Identify the heading level entries to be displayed in the contents
.* window
.*--------------------------------------------------------------------

:h1 id=content1 x=left y=top width=100% height=100% scroll=both
    clear.Fatal Exceptions definition and values.
:p.The except package has been designed to gather the necessary information
when a fatal exception occurs. A fatal exception is an operating system defined
class of error condition which causes the end of the thread and the process
when it occurs.
:p.The exceptions have a 32 bits value and are grouped by severity. The 2 first
bits defined the severity. These 2 bits are set for a fatal exception. The most
current exception when programming is the XCPT_ACCESS_VIOLATION (0xC0000005).
:p. Portable, Fatal, Hardware-Generated Exceptions:
:xmp.
 ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿
 ³Exception Name                  ³Value         ³Related Trap  ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³  XCPT_ACCESS_VIOLATION         ³0xC0000005    ³0x09, 0x0B,   ³
 ³                                ³              ³0x0C, 0x0D,   ³
 ³  ExceptionInfo[ 0 ] - Flags    ³              ³0x0E          ³
 ³      XCPT_UNKNOWN_ACCESS  0x0  ³              ³              ³
 ³      XCPT_READ_ACCESS     0x1  ³              ³              ³
 ³      XCPT_WRITE_ACCESS    0x2  ³              ³              ³
 ³      XCPT_EXECUTE_ACCESS  0x4  ³              ³              ³
 ³      XCPT_SPACE_ACCESS    0x8  ³              ³              ³
 ³      XCPT_LIMIT_ACCESS    0x10 ³              ³              ³
 ³  ExceptionInfo[ 1 ] - FaultAddr³              ³              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_INTEGER_DIVIDE_BY_ZERO     ³0xC000009B    ³0             ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_FLOAT_DIVIDE_BY_ZERO       ³0xC0000095    ³0x10          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_FLOAT_INVALID_OPERATION    ³0xC0000097    ³0x10          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_ILLEGAL_INSTRUCTION        ³0xC000001C    ³0x06          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_PRIVILEGED_INSTRUCTION     ³0xC000009D    ³0x0D          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_INTEGER_OVERFLOW           ³0xC000009C    ³0x04          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_FLOAT_OVERFLOW             ³0xC0000098    ³0x10          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_FLOAT_UNDERFLOW            ³0xC000009A    ³0x10          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_FLOAT_DENORMAL_OPERAND     ³0xC0000094    ³0x10          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_FLOAT_INEXACT_RESULT       ³0xC0000096    ³0x10          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_FLOAT_STACK_CHECK          ³0xC0000099    ³0x10          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_DATATYPE_MISALIGNMENT      ³0xC000009E    ³0x11          ³
 ³                                ³              ³              ³
 ³  ExceptionInfo[ 0 ] - R/W flag ³              ³              ³
 ³  ExceptionInfo[ 1 ] - Alignment³              ³              ³
 ³  ExceptionInfo[ 2 ] - FaultAddr³              ³              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_BREAKPOINT                 ³0xC000009F    ³0x03          ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_SINGLE_STEP                ³0xC00000A0    ³0x01          ³
 ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ
:exmp.
:p.Portable, Fatal, Software-Generated Exceptions:
:xmp.
 ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿
 ³Exception Name                  ³Value         ³Related Trap  ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_IN_PAGE_ERROR              ³0xC0000006    ³0x0E          ³
 ³                                ³              ³              ³
 ³  ExceptionInfo[ 0 ] - FaultAddr³              ³              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_PROCESS_TERMINATE          ³0xC0010001    ³              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_ASYNC_PROCESS_TERMINATE    ³0xC0010002    ³              ³
 ³                                ³              ³              ³
 ³  ExceptionInfo[ 0 ] - TID of   ³              ³              ³
 ³           terminating thread   ³              ³              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_NONCONTINUABLE_EXCEPTION   ³0xC0000024    ³              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_INVALID_DISPOSITION        ³0xC0000025    ³              ³
 ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ
:exmp.
:p. Non-Portable, Fatal Exceptions:
:xmp.
 ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿
 ³Exception Name                  ³Value         ³Related Trap  ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_INVALID_LOCK_SEQUENCE      ³0xC000001D    ³              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_ARRAY_BOUNDS_EXCEEDED      ³0xC0000093    ³0x05          ³
 ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ
:exmp.
:p.Fatal Signal Exceptions:
:xmp.
 ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿
 ³Exception Name                  ³Value         ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³XCPT_SIGNAL                     ³0xC0010003    ³
 ³                                ³              ³
 ³  ExceptionInfo[ 0 ] - Signal   ³              ³
 ³                       Number   ³              ³
 ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ
:exmp.
:p.When investigating an exception caused by your code you first need to know
where it occurred.
:p.Exception handlers
:h1 id=content2 x=left y=top width=100% height=100% scroll=both
    clear.Exception Handlers and investigating fatal exception
:p.Exception handlers are OS/2 2.x programming facilities which allow the
programmer to act when the exception occur.
:p.There must be at least one exception handler defined per thread of the
process to handle the exceptions which may occur in that thread.
:p.The exception handler is a callback function which gets called with
several parameter among which a pointer to CONTEXTRECORD which contains
all the thread and register information at the time the failure occurred.
:p.Some of the registers are essential to investigate the TRAPs.
:dl tsize=20.
:dt.CS:dd.This is the code segment register. Its value is the current code
segment being executed. If the application is a 16&colon.16 bit segmented code is
must be matched to one of the .EXE objects  orone of the DLLs code object in
memory at that time. For 32 bit linear code (C-Set/2 C-Set++) CS contains the
value of the OS/2 segment mapping all executable user memory.
:dt.IP or EIP:dd.IP or EIP (resp. 16&colon.16 or 32 code) is the segment containing
the instruction pointer which is the offset from the beginning of the segment
of the failing instruction. If EIP is greater than 0x0000FFFF then the code
being executed is 32 bits linear else it is 16&colon.16 segmented.
:dt.ESP or SP:dd.Those registers give the current stack pointer.
:dt.EBP or BP:dd.Those registers give the address of the base pointer.
The base pointer should contain the stack address or offset where
the calling function address has been saved.
:p.Usually the stack frame respects the following convention which
allows to find from where the failing code was called once one has the
stack dump.
:xmp.
 ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿
 ³                    Stack content                             ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÂÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³     16&colon.16 bit code            ³     32 bit code              ³
 ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
 ³       <ÄÄÄÄ 2 Bytes ÄÄÄÄÄ>    ³        <ÄÄÄÄ 4 Bytes ÄÄÄÄÄ>  ³
 ³       ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿    ³        ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿  ³
 ³    .  .                       ³     .  .                     ³
 ³    ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´    ³     ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´  ³
 ³    ÀÄ<  previous caller  ³    ³     ÀÄ<  previous caller  ³  ³
 ³    Ú >  BP etc ...       ³    ³     Ú >  EBP etc ...      ³  ³
 ³    ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´    ³     ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´  ³
 ³    ³  . caller's local   .    ³     ³  . caller's local   .  ³
 ³    ³  . parms            .    ³     ³  . parms            .  ³
 ³    ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´    ³     ³  .                  .  ³
 ³    ³  ³ Caller return IP ³    ³     ³  .                  .  ³
 ³    ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´    ³     ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´  ³
 ³    ³  ³ Caller return CS ³    ³     ³  ³ Caller return EIP³  ³
 ³    ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´    ³     ³  ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´  ³
 ³    ÀÄÄ< Caller's BP      ³    ³     ÀÄÄ< Caller's EBP     ³  ³
 ³ BP -> ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´    ³ EBP -> ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´  ³
 ³       .  function local  .    ³        .  function local  .  ³
 ³       .  parameters      .    ³        .  parameters      .  ³
 ³                               ³                              ³
 ³ SP -> ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ    ³ ESP -> ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ  ³
 ³       <ÄÄÄÄ 2 Bytes ÄÄÄÄÄ>    ³        <ÄÄÄÄ 4 Bytes ÄÄÄÄÄ>  ³
 ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÁÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ
:exmp.

:dt.CSLIM:dd.For 16&colon.16 bit code this gives the size of the failing code object.
:edl.

:h1 id=content3 x=left y=top width=100% height=100% scroll=both
    clear.EXCEPT and EXCEPTQ Trap analysis exception handlers.
:p.EXCEPT and EXCEPTQ are now identical. They are exception handlers which when
a trap occurs save the registers in a file named xxxx.TRP (xxxx=Pid,Tid)
together with the Loaded modules code and data objects addresses, and also
the failing thread stack dump and the call stack analysis.  If the
debugging information is present in the executable then the source line
numbers will be too in the output .TRP file.  Trapper is an IBM C/2 program
which shows how to implement the call to 32 bits exception handler from a
16&colon.16 bits program Sample in a C-Set/2 program which shows the usage from
a 32 bit program. Enter Trapper (16&colon.16) or Sample (0&colon.32) to
generate a sample trap and the xxxxxx.TRP file.


:h1 id=content5 x=left y=top width=100% height=100% scroll=both
    clear.TRAPTRAP Non intrusive exception catcher
:p. TRAPTRAP is a sample Trap catcher code using DosDebug.
Usage is

  TRAPTRAP [optional watch points] trapping_program arguments

optional watch points syntax is :
  /address1 [ /address2 [/address3 [ /address4 ]]]

where address1 (2,3,4) are the linear addresses to watch up to 4
addresses can be specified

sample provided use > TRAPTRAP TEST
where test.exe will trap

sample watch point provided use > TRAPTRAP /20000 WATCH
where watch.exe will write at linear address 20000
run 1st watch alone to check address.

it generates a PROCESS.TRP file similar to EXCEPTQ's
:h1 id=CSET x=left y=top width=100% height=100% scroll=both
    clear.Using Exception handler with C-Set/2 and C-Set++
:p. Usage with C-Set/2 and C-Set++ is very simple. Just add the following 2
lines in your code containing the main().
:xmp.
#pragma handler(main)
#pragma map(_Exception,"MYHANDLER")
:exmp.
:p.First line tells compiler to install an exception handler for "main". You
should also add a handler for all thread functions using #pragma handler(xxxx)
where xxxx is the name of the thread function parameter to _beginthread().
:p.Second line tells compiler to use the handler "MYHANDLER" (contained in
EXCEPTQ.DLL or EXCEPT.DLL) instead of the default C-Set handler named _Exception.
:p.See the "sample.c" sample for source. The code object should be linked with
EXCEPTQ.LIB (or EXCEPT.LIB).
:h1 id=Symbol x=left y=top width=100% height=100% scroll=both
    clear.Getting Symbolic information in Trap files
:p.Use the MAPSYM tool from the toolkit against your executables (.EXE,.DLL)
 .MAP files and put the resulting .SYM files in the same directory where the
executable resides. The EXCEPTQ (and EXCEPT) exception handlers will
automatically locate them and use them to find the closest symbols from the
failing address and calling functions when walking the stack. Thus you
will have the symbolic name of the functions (if available).
:p.I'll make line numbering will be available when MAPSYM will be able to
process LINK386 generated maps with /LI line information.
:h1 id=COPYDBG x=left y=top width=100% height=100% scroll=both
    clear.using COPYDBG to ship debug information separately
:p.EXCEPT and EXCEPTQ use the debug inforamtion if present in the executable
to locate the failing line of code and source file. However if you do not
want to ship the modules with the debug (codeview) information and ship it only
if problems occur, then link with /CO first, use the COPYDBG command to copy the debug
information from the executables (EXE or DLL), then link without /CO to ship.
COPYDBG creates files with .DBG extension, those files containing only the
debugging information.
:h1 id=FORCEXIT x=left y=top width=100% height=100% scroll=both
    clear.Using EXCEPTQ's ForceExit
:p.EXCEPTQ has a ForceExit function which allows processes to exit even
if threads are in kernel wait. It intentionally generates an invisible trap,
having resumed all frozen threads before.
:p.Thread calling forcexit should not by in a Critical Section. See the
EXITTEST.c for sample use.
:euserdoc.
