# $Id: $

BASE = sample3

.SUFFIXES:

.SUFFIXES: .c

CC = icc
LINK = ilink

$(BASE).exe:  \
  $(BASE).obj \
  $(BASE).mak
   $(CC) @<<$(BASE).lrf
 /B" /de /nologo /map /li /st:8192"
 /Fe"$(BASE).exe" exceptq.lib
$(BASE).obj
<<

.c.obj:
   $(CC) /Tl5 /Tdc /Sp1 /Ss /Q /Fi /Si /Gh /Ti /W2 /Gm /Gd /G4 /Tm /Wprorearet /C $*.c

