# $Id: traptrap.mak,v 1.2 2005/08/08 17:06:22 root Exp $

.SUFFIXES:

.SUFFIXES: .c

traptrap.exe:  \
  traptrap.obj \
  traptrap.def \
  traptrap.mak
   @ilink @<<traptrap.lrf
     /DE /IG /M /NOL /PM:VIO
     traptrap.obj
     dis386.lib
     traptrap.def
<<

.c.obj:
   icc /Sm /Ss /Lx /O- /Ti /Gm /Ge+ /C $*.c

traptrap.obj:  traptrap.c omf.h traptrap.mak
