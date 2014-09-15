/*********************************************************************
  bcoa.h - Borland Open Architecture debug data structures
  $Id: $

  Debug info definitions apply to Borland Open Architecture debug format
  Requires hlldbg.h for common definitions

  27 May 08 SHL Baseline
*/

#ifndef BCOADBG_H
#define BCOADBG_H

#pragma pack(1)

/* Known formats

   FB09		Borland Open Architecture BC2.0 OS/2
*/

#define         BCOADBG_SIG	0x4246	/* "FB" Borland OA signature */

#define SSTMODULE_BCOA 0x120
#define SSTTYPES_BCOA 0x121
#define SSTSYMBOLS_BCOA 0x124
#define SSTALIGNSYM_BCOA 0x125
#define SSTSRCMODULE_BCOA 0x127
#define SSTGLOBALSYM_BCOA 0x129
#define SSTGLOBALTYPES_BCOA 0x12b
#define SSTNAMES_BCOA 0x130

#pragma pack()

#endif // BCOADBG_H
