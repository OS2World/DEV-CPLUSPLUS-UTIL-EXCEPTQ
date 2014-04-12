/* $Id: $
  sample4.c test trap in 16 bit function

  adapted from code created by Marc Fiammante December 1992
*/


#include <stdio.h>
#include <stdlib.h>

/* Install exception handler for main */

int main(int argc, char **argv);

#pragma handler (main)

/* Use MYHANDLER instead of default _Exception handler */
#pragma map (_Exception,"MYHANDLER")


void Func(void);

extern void _Far16 TrapFunc16(void);

int main(int argc, char **argv)
{
    printf("Exception handler has been set by compiler\n");
    Func();
    return 0;
}

void Func(void) {
    TrapFunc16();
}

