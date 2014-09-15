/* $Id: $
*/

/**********************************************************************/
/*                                                                    */
/*  SAMPLE                                                            */
/*                                                                    */
/* SAMPLE 32 bit program to access EXCEPTQ.DLL exception handler      */
/* SAMPLE generates a TRAP to demonstrate information gathering       */
/* C-SET/2 compiler complies that code                                */
/*                                                                    */
/* Version: 2.2             |   Marc Fiammante (FIAMMANT at LGEVM2)   */
/*                          |   La Gaude FRANCE                       */
/*                                                                    */
/* History:                                                           */
/* --------                                                           */
/*                                                                    */
/* created: Marc Fiammante December 1992                              */
/**********************************************************************/

#include <stdio.h>
#include <stdlib.h>

/* Following line to tell C-Set compiler to install an exception handler */
/* for main                                                              */

int main(int argc, char **argv);

#pragma handler (main)

/* Following line to tell C-Set compiler to use MYHANDLER instead of     */
/* default _Exception handler                                            */
#pragma map (_Exception,"MYHANDLER")

// #define TRYTRAP16

#ifdef TRYTRAP16
void _Far16 TrapFunc16(void);
#else
void TrapFunc(void);
#endif

int main(int argc, char **argv)
{
    printf("Exception handler has been set by compiler\n");
    printf("Generating the TRAP from function\n");
#   ifdef TRYTRAP16
    TrapFunc16();
#   else
    TrapFunc();
#   endif
    return 0;
}

#ifdef TRYTRAP16

void _Far16 TrapFunc16(void) {
    char * Test;
    Test=0;
    *Test=0;
}

#else

void TrapFunc(void) {
    char * Test;
    Test=0;
    *Test=0;
}
#endif
