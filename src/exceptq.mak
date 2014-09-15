#
# exceptq.mak - build exceptq.dll v7.1
#
# Tools used:  nmake32  vacpp(v3.65)  ilink(v5)  implib  mapsym
# Note:  '@echo' separates each tool's output with a blank line

.SUFFIXES:

.SUFFIXES: .c

all: exceptq.dll

exceptq.dll:  \
  exceptq.obj \
  exq_cv.obj \
  exq_dbg.obj \
  exq_rpt.obj \
  exq_sym.obj \
  exceptq.def \
  exceptq.mak
  @echo
  ilink @<<exceptq.lrf
    /DLL /EXEPACK:2 /NOI /M /NOL /OPTFUNC /NOSEGORDER
    /OUT:exceptq.dll
    exceptq.obj
    exq_cv.obj
    exq_dbg.obj
    exq_rpt.obj
    exq_sym.obj
    exceptq.def
<<
  @echo
  implib /nologo exceptq.lib exceptq.def
  @echo
  mapxqs exceptq

.c.obj:
  @echo
  icc /Ge- /Gl+ /Gm /O+ /Q /Sm /Ss /W3 /C $*.c

exceptq.obj:  exceptq.c  exq.h exceptq.mak
exq_cv.obj:   exq_cv.c   exq.h exceptq.mak omf.h hlldbg.h
exq_dbg.obj:  exq_dbg.c  exq.h exceptq.mak omf.h hlldbg.h
exq_rpt.obj:  exq_rpt.c  exq.h exceptq.mak distorm.h
exq_sym.obj:  exq_sym.c  exq.h exceptq.mak sym.h xqs.h

