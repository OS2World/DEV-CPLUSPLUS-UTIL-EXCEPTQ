/**********************************************************************/
/**********************************************************************/
/*                                                                    */
/*  TEST                                                              */
/*                                                                    */
/* TEST is a test program which generates a trap just to demonstrate  */
/* TRAPTRAP usage                                                     */
/**********************************************************************/
/* Version: 6.3             |   Marc Fiammante (FIAMMANT at LGEPROFS) */
/*                          |   La Gaude FRANCE                       */
/*                          |   Bill Siddall   (SIDDALL at RTPNOTES)  */
/**********************************************************************/
/*                                                                    */
/**********************************************************************/
/* History:    Bill Siddall added local variable dump test            */
/* --------                                                           */
/*                                                                    */
/**********************************************************************/
#  pragma map(_Exception, "MYHANDLER")
#  pragma handler(main)
#include <string.h>
#include <stddef.h>
int iiix=224;
float ffff=3.14;
typedef  struct s
  {
    int i;
    char text[5];
  } _s;
void f3(char *p)
{
  int *q;
  q = NULL;
  *q = 0;
}
void f2(float f)
{
  int i;
  char text[] = "This is a test";
  _s ss;
  _s *p;
  i = 0;
  f = 19.0;
  ss.i = 8;
  strcpy(ss.text, "Test");
  p = &ss;
  f3(text);
}
void f1(int i)
{
  float f;
  char text[] = "This is a test";
  float *p;
  i = 7;
  f = 13.0;
  p = &f;
  f2(f);
}
void main(void)
{
  int i;
  float f;
  char text[] = "This is a test";
  int *p;
  i = 4;
  f = 99.0;
  p = &i;
  f1(i);
}
