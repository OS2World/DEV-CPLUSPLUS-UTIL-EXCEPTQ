
// wcc -bt=os2 -nt_TEXT16 -nd=D16 -s -zl trapfunc16.c

# pragma data_seg ("CONST16")
void _Far16 cdecl TrapFunc16(void);

void _Far16 TrapFunc16(void) {
    char _far *Test;
    Test=0;
    *Test=0;
}
