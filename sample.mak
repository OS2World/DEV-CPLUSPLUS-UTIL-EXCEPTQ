# IBM Developer's Workframe/2 Make File Creation run at 19:35:17 on 08/30/93

# Make File Creation run in directory:
#   E:\VTX\VTXKER;

.SUFFIXES:

.SUFFIXES: .c .cpp .cxx

sample.EXE:  \
  sample.OBJ \
  sample.MAK
   ICC.EXE @<<
 /B" /de /nologo /map /li /st:8192"
 /Fe"sampleq.EXE" exceptq.lib
sample.OBJ
<<

{.}.c.obj:
   ICC.EXE /Tl5 /Tdc /Sp1 /Ss /Q /Fi /Si /Gh /Ti /W2 /Gm /Gd /G4 /Tm /Wprorearet /C   .\$*.c

{.}.cpp.obj:
   ICC.EXE /Tl5 /Tdc /Sp1 /Ss /Q /Fi /Si /Gh /Ti /W2 /Gm /Gd /G4 /Tm /C   .\$*.cpp

{.}.cxx.obj:
   ICC.EXE /Tl5 /Tdc /Sp1 /Ss /Q /Fi /Si /Gh /Ti /W2 /Gm /Gd /G4 /Tm /C   .\$*.cxx

