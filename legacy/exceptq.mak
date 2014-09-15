# exceptq.mak - build exceptq.dll
# $Id: exceptq.mak,v 1.5 2010/04/28 15:33:10 Steven Exp $

# 26 Jul 02 SHL - Rework for VAC 3.08
# 02 Aug 05 SHL - Clean up
# 03 Aug 05 SHL - Add missing dependencies
# 23 May 08 SHL - Add inf target
# 03 Dec 09 SHL - Add lxlite target
# 25 Apr 10 SHL - Add exceptq.sym target

.SUFFIXES:

.SUFFIXES: .c

all: exceptq.dll exceptq.sym

exceptq.dll exceptq.map:  \
  exceptq.obj \
  exceptq.def \
  exceptq.mak
  ilink @<<exceptq.lrf
    /DE /IG /M /NOL /PM:VIO
    /OUT:exceptq.dll
    exceptq.obj
    dis386.lib
    exceptq.def
<<
  implib exceptq.lib exceptq.def

exceptq.sym: exceptq.map
  mapsym exceptq

.c.obj:
  icc /Ti /Sm /Ss /Gm /Ge- /W3 /C $*.c

exceptq.obj:  exceptq.c sym.h omf.h exceptq.mak

inf: except.inf

except.inf: except.ipf
  ipfc /i $*.ipf
  ren $@ $@

lxlite: exceptq.dll
  lxlite -X- -B- $?
  

# The end
