# $Id: sample.mak,v 1.2 2005/08/08 17:02:28 root Exp $

BASE = sample5

.SUFFIXES:

.SUFFIXES: .c

DTRYTRAP16 = /DTRYTRAP16=1

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
   $(CC) /Tl5 /Sp1 /Ss /Ti /Gm /G4 /W3 $(DTRYTRAP16) /C $*.c

#  $(CC) /Tl5 /Tdc /Sp1 /Ss /Q /Fi /Si /Gh /Ti /W2 /Gm /Gd /G4 /Tm /Wprorearet /C $*.c

