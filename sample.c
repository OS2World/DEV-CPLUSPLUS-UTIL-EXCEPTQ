/**********************************************************************/
/*                           IBM Internal Use Only                    */
/**********************************************************************/
/*                                                                    */
/*  SAMPLE                                                            */
/*                                                                    */
/* SAMPLE 32 bit program to access EXCEPTQ.DLL exception handler      */
/* SAMPLE generates a TRAP to demonstrate information gathering       */
/* C-SET/2 compiler complies that code                                */
/**********************************************************************/
/* Version: 2.2             |   Marc Fiammante (FIAMMANT at LGEVM2)   */
/*                          |   La Gaude FRANCE                       */
/**********************************************************************/
/*                                                                    */
/**********************************************************************/
/* History:                                                           */
/* --------                                                           */
/*                                                                    */
/* created: Marc Fiammante December 1992                              */
/**********************************************************************/

/* Following line to tell C-Set compiler to install an exception handler */
/* for main                                                              */
#pragma handler(main)
/* Following line to tell C-Set compiler to use MYHANDLER instead of     */
/* default _Exception handler                                            */
#pragma map (_Exception,"MYHANDLER")

#include <stdio.h>
#include <stdlib.h>

void TrapFunc(void);

main()
{

    printf("Exception handler has been set by compiler\n");
    printf("Generating the TRAP from function\n");
    TrapFunc();
}
void TrapFunc() {
    char * Test;
    Test=0;
    *Test=0;
}
