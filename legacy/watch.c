/**********************************************************************/
/**********************************************************************/
/*                                                                    */
/*  WATCH                                                             */
/*                                                                    */
/* SAMPLE 32 bit program to show traptrap usage with Watchpoints      */
/* Call it first to get the Test variable address then                */
/* call it using traptrap /address watch.exe                          */
/* to see process.trp output                                          */
/**********************************************************************/
/* Version: 2.7             |   Marc Fiammante (FIAMMANT at LGEVM2)   */
/*                          |   La Gaude FRANCE                       */
/**********************************************************************/
/*                                                                    */
/**********************************************************************/
/* History:                                                           */
/* --------                                                           */
/*                                                                    */
/* created: Marc Fiammante November 1993                              */
/**********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <direct.h>
#include <process.h>
#include <conio.h>

#define INCL_BASE

#include <os2.h>
#include <bse.h>

CHAR Test='0';

main()
{
   printf("Address of Test variable is %p\n",&Test);
   printf("Use the following command : TRAPTRAP /%p WATCH.EXE \n",&Test);
   Test='1';  /* Should get result of watch point in PROCESS.TRP file */
}
