# sym.mak - make sym.exe with VAC 3.65
# $Id: sym.mak,v 1.3 2006/03/17 21:55:20 root Exp $

# Copyright (c) 2004 Steven Levine and Associates, Inc.
# All rights reserved.

# 29 Jul 04 SHL Baseline

# Assumes standard Warp4 Toolkit
# Support DEBUG

BASE = sym

.SUFFIXES:
.SUFFIXES: .c

CC = icc
LINK = ilink

!ifdef DEBUG
CFLAGS = /Sp1 /Ss /Q /Ss /Ti /W3 /G4 /c
!else
CFLAGS = /Sp1 /Ss /Q /Ss /Ti /W3 /G4 /c
!endif

!ifdef DEBUG
LFLAGS = /debug /map /nologo /pmtype:vio
!else
LFLAGS = /exepack:2 /map /nologo /pmtype:vio
!endif

.c.obj:
  $(CC) $(CFLAGS) $<

all: $(BASE).exe

$(BASE).exe: \
  $(BASE).obj \
  $(BASE).mak
  $(LINK) @<<$(BASE).lrf
    $(LFLAGS)
    /OUT:$(BASE).exe
    $(BASE).obj
<<
  mapsym $(BASE)

sym.c : sym.h

clean:
  -del $(BASE).exe
  -del $(BASE).obj
  -del $(BASE).map
  -del $(BASE).sym
  -del $(BASE).lrf

# The end
