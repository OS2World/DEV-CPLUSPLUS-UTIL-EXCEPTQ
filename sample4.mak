# $Id: $

BASE = sample4

.SUFFIXES:

.SUFFIXES: .c

CC = icc
LINK = ilink

$(BASE).exe:  \
  $(BASE).obj \
  trapfunc16.obj \
  $(BASE).mak
   $(CC) @<<$(BASE).lrf
 /B" /de /nologo /map /li /st:8192"
 /Fe"$(BASE).exe" exceptq.lib
$(BASE).obj trapfunc16.obj
<<

.c.obj:
   $(CC) /Tl5 /Sp1 /Ss /Ti /Gm /G4 /W3 /C $*.c

#  $(CC) /Tl5 /Tdc /Sp1 /Ss /Q /Fi /Si /Gh /Ti /W2 /Gm /Gd /G4 /Tm /Wprorearet /C $*.c

