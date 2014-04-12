# IBM Developer's Workframe/2 Make File Creation run at 19:30:24 on 10/09/92

# Make File Creation run in directory:
#   H:\EXCEPT;

.SUFFIXES:

.SUFFIXES: .c

TRAPTRAP.EXE:  \
  TRAPTRAP.OBJ \
  TRAPTRAP.DEF \
  TRAPTRAP.MAK
   @REM @<<TRAPTRAP.@0
     /M /W /CO +
     TRAPTRAP.OBJ
     TRAPTRAP.EXE

     DIS386.LIB
     TRAPTRAP.DEF;
<<
   LINK386.EXE @TRAPTRAP.@0

{.}.c.obj:
   ICC.EXE /Sm /Ss /Lx /O- /Ti /Gm /Ge+ /C .\$*.c

!include TRAPTRAP.DEP
