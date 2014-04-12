# exceptq.mak - build exceptq.dll
# $Id: exceptq.mak,v 1.4 2008/05/24 23:26:38 Steven Exp $

# 26 Jul 02 SHL - Rework for VAC 3.08
# 02 Aug 05 SHL - Clean up
# 03 Aug 05 SHL - Add missing dependencies
# 23 May 08 SHL - Add inf target

.SUFFIXES:

.SUFFIXES: .c

exceptq.dll:  \
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

.c.obj:
  icc /Ti /Sm /Ss /Gm /Ge- /W3 /C $*.c

exceptq.obj:  exceptq.c sym.h omf.h exceptq.mak

inf: except.inf

except.inf: except.ipf
  ipfc /i $*.ipf
  ren $@ $@

# The end
