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
 ��������������������������������������������������������������Ŀ
 �Exception Name                  �Value         �Related Trap  �
 ��������������������������������������������������������������Ĵ
 �  XCPT_ACCESS_VIOLATION         �0xC0000005    �0x09, 0x0B,   �
 �                                �              �0x0C, 0x0D,   �
 �  ExceptionInfo[ 0 ] - Flags    �              �0x0E          �
 �      XCPT_UNKNOWN_ACCESS  0x0  �              �              �
 �      XCPT_READ_ACCESS     0x1  �              �              �
 �      XCPT_WRITE_ACCESS    0x2  �              �              �
 �      XCPT_EXECUTE_ACCESS  0x4  �              �              �
 �      XCPT_SPACE_ACCESS    0x8  �              �              �
 �      XCPT_LIMIT_ACCESS    0x10 �              �              �
 �  ExceptionInfo[ 1 ] - FaultAddr�              �              �
 ��������������������������������������������������������������Ĵ
 �XCPT_INTEGER_DIVIDE_BY_ZERO     �0xC000009B    �0             �
 ��������������������������������������������������������������Ĵ
 �XCPT_FLOAT_DIVIDE_BY_ZERO       �0xC0000095    �0x10          �
 ��������������������������������������������������������������Ĵ
 �XCPT_FLOAT_INVALID_OPERATION    �0xC0000097    �0x10          �
 ��������������������������������������������������������������Ĵ
 �XCPT_ILLEGAL_INSTRUCTION        �0xC000001C    �0x06          �
 ��������������������������������������������������������������Ĵ
 �XCPT_PRIVILEGED_INSTRUCTION     �0xC000009D    �0x0D          �
 ��������������������������������������������������������������Ĵ
 �XCPT_INTEGER_OVERFLOW           �0xC000009C    �0x04          �
 ��������������������������������������������������������������Ĵ
 �XCPT_FLOAT_OVERFLOW             �0xC0000098    �0x10          �
 ��������������������������������������������������������������Ĵ
 �XCPT_FLOAT_UNDERFLOW            �0xC000009A    �0x10          �
 ��������������������������������������������������������������Ĵ
 �XCPT_FLOAT_DENORMAL_OPERAND     �0xC0000094    �0x10          �
 ��������������������������������������������������������������Ĵ
 �XCPT_FLOAT_INEXACT_RESULT       �0xC0000096    �0x10          �
 ��������������������������������������������������������������Ĵ
 �XCPT_FLOAT_STACK_CHECK          �0xC0000099    �0x10          �
 ��������������������������������������������������������������Ĵ
 �XCPT_DATATYPE_MISALIGNMENT      �0xC000009E    �0x11          �
 �                                �              �              �
 �  ExceptionInfo[ 0 ] - R/W flag �              �              �
 �  ExceptionInfo[ 1 ] - Alignment�              �              �
 �  ExceptionInfo[ 2 ] - FaultAddr�              �              �
 ��������������������������������������������������������������Ĵ
 �XCPT_BREAKPOINT                 �0xC000009F    �0x03          �
 ��������������������������������������������������������������Ĵ
 �XCPT_SINGLE_STEP                �0xC00000A0    �0x01          �
 ����������������������������������������������������������������
:exmp.
:p.Portable, Fatal, Software-Generated Exceptions:
:xmp.
 ��������������������������������������������������������������Ŀ
 �Exception Name                  �Value         �Related Trap  �
 ��������������������������������������������������������������Ĵ
 �XCPT_IN_PAGE_ERROR              �0xC0000006    �0x0E          �
 �                                �              �              �
 �  ExceptionInfo[ 0 ] - FaultAddr�              �              �
 ��������������������������������������������������������������Ĵ
 �XCPT_PROCESS_TERMINATE          �0xC0010001    �              �
 ��������������������������������������������������������������Ĵ
 �XCPT_ASYNC_PROCESS_TERMINATE    �0xC0010002    �              �
 �                                �              �              �
 �  ExceptionInfo[ 0 ] - TID of   �              �              �
 �           terminating thread   �              �              �
 ��������������������������������������������������������������Ĵ
 �XCPT_NONCONTINUABLE_EXCEPTION   �0xC0000024    �              �
 ��������������������������������������������������������������Ĵ
 �XCPT_INVALID_DISPOSITION        �0xC0000025    �              �
 ����������������������������������������������������������������
:exmp.
:p. Non-Portable, Fatal Exceptions:
:xmp.
 ��������������������������������������������������������������Ŀ
 �Exception Name                  �Value         �Related Trap  �
 ��������������������������������������������������������������Ĵ
 �XCPT_INVALID_LOCK_SEQUENCE      �0xC000001D    �              �
 ��������������������������������������������������������������Ĵ
 �XCPT_ARRAY_BOUNDS_EXCEEDED      �0xC0000093    �0x05          �
 ����������������������������������������������������������������
:exmp.
:p.Fatal Signal Exceptions:
:xmp.
 �����������������������������������������������Ŀ
 �Exception Name                  �Value         �
 �����������������������������������������������Ĵ
 �XCPT_SIGNAL                     �0xC0010003    �
 �                                �              �
 �  ExceptionInfo[ 0 ] - Signal   �              �
 �                       Number   �              �
 �������������������������������������������������
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
 ��������������������������������������������������������������Ŀ
 �                    Stack content                             �
 ��������������������������������������������������������������Ĵ
 �     16&colon.16 bit code            �     32 bit code              �
 ��������������������������������������������������������������Ĵ
 �       <���� 2 Bytes �����>    �        <���� 4 Bytes �����>  �
 �       ������������������Ŀ    �        ������������������Ŀ  �
 �    .  .                       �     .  .                     �
 �    �  ������������������Ĵ    �     �  ������������������Ĵ  �
 �    ��<  previous caller  �    �     ��<  previous caller  �  �
 �    � >  BP etc ...       �    �     � >  EBP etc ...      �  �
 �    �  ������������������Ĵ    �     �  ������������������Ĵ  �
 �    �  . caller's local   .    �     �  . caller's local   .  �
 �    �  . parms            .    �     �  . parms            .  �
 �    �  ������������������Ĵ    �     �  .                  .  �
 �    �  � Caller return IP �    �     �  .                  .  �
 �    �  ������������������Ĵ    �     �  ������������������Ĵ  �
 �    �  � Caller return CS �    �     �  � Caller return EIP�  �
 �    �  ������������������Ĵ    �     �  ������������������Ĵ  �
 �    ���< Caller's BP      �    �     ���< Caller's EBP     �  �
 � BP -> ������������������Ĵ    � EBP -> ������������������Ĵ  �
 �       .  function local  .    �        .  function local  .  �
 �       .  parameters      .    �        .  parameters      .  �
 �                               �                              �
 � SP -> ��������������������    � ESP -> ��������������������  �
 �       <���� 2 Bytes �����>    �        <���� 4 Bytes �����>  �
 ����������������������������������������������������������������
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