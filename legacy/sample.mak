# $Id: sample.mak,v 1.3 2007/09/13 01:14:15 Steven Exp $

# 12 Sep 07 SHL Support TRYTRAP16

BASE = sample

.SUFFIXES:

.SUFFIXES: .c

!ifdef TRYTRAP16
DTRYTRAP16 = /DTRYTRAP16=1
!endif

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

