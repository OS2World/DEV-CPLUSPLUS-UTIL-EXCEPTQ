/*********************************************************************
  sym.c - simple .sym file dump
  $Id: sym.c,v 1.5 2008/05/24 23:27:20 Steven Exp $

 29 Jul 04 SHL Show address as seg:address
 01 Jul 05 SHL Correct SymOffset def
 01 Jul 05 SHL Debug code for large file debug (DBGLRG)
 06 May 08 SHL Add code to adjust for oversize symbol files

 vim: set tabs=3

*/


#define INCL_BASE
#define INCL_DOS
#include <os2.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "sym.h"

// #define DBGLRG 1

int main(int argc,char *argv[])
{
   FILE *fpSymFile;
   MAPDEF MapDef;
   SEGDEF SegDef;
   SEGDEF *pSegDef;
   SYMDEF32 SymDef32;
   SYMDEF16 SymDef16;
   CHAR	Buffer[258];			// fixme to not overflow
   USHORT usSegNum;
   USHORT usSymNum;
   ULONG ulSegOffset;
   ULONG ulNextSegOffset;		// Large file support
   USHORT usSymOffset;
   ULONG ulSymPtrOffset;
   USHORT usLastSymOffset;		// 06 May 08 SHL
   ULONG ulSymOffsetAdjust;		// 06 May 08 SHL
   ULONG ulSymPtrAdjust;		// 06 May 08 SHL large file support

   if (argc==1) {
      printf("No file name entered\n");
      exit(1);
   } else {
      fpSymFile=fopen(argv[1],"rb");
      if (fpSymFile==0) {
	 perror("Error opening file ");
	 exit(99);
      } /* endif */
   } /* endif */

   fread(&MapDef,sizeof(MAPDEF),1,fpSymFile);

   Buffer[0]= MapDef.achModName[0];
   fread(Buffer + 1,1,MapDef.cbModName,fpSymFile);
   Buffer[MapDef.cbModName]=0;

#  ifdef DBGLRG
   printf("\nOffset 0x00000000 MapDef ppNextMap 0x%X bFlags 0x%X bReserved1 0x%X pSegEntry 0x%X\n"
	  " cConsts %d pConstDef 0x%X cSegs %d ppSegDef 0x%X\n"
	  " cbMaxSym %d cbModName %d achModName %s\n",
	  MapDef.ppNextMap, MapDef.bFlags, MapDef.bReserved1, MapDef.pSegEntry,
	  MapDef.cConsts, MapDef.pConstDef, MapDef.cSegs, MapDef.ppSegDef,
	  MapDef.cbMaxSym, MapDef.cbModName, Buffer);
#  endif

   ulSegOffset=SEGDEFOFFSET(MapDef);

   for (usSegNum=0;usSegNum<MapDef.cSegs;usSegNum++) {
#	ifdef DBGLRG
	printf("\nulSegOffset 0x%08X Segment #%d",ulSegOffset,usSegNum+1);
#	endif

	if (fseek(fpSymFile,ulSegOffset,SEEK_SET)) {
	   perror("Seek error ");
	   exit(1);
	}

	fread(&SegDef,sizeof(SEGDEF),1,fpSymFile);
	Buffer[0]= SegDef.achSegName[0];
	fread(Buffer + 1,1,SegDef.cbSegName,fpSymFile);
	Buffer[SegDef.cbSegName]=0;
#	ifdef DBGLRG
	printf(" ppNextSeg 0x%X cSymbols %d pSymDef 0x%X\n"
	       " wSegNum %d wInstance0 0x%X wInstance1 0x%X wInstance2 0x%X\n"
	       " bFlags 0x%X (%s) bReserved1 0x%X ppLineDef 0x%X\n"
	       " bIsSegLoaded %d bCurrInstance %d cbSegName %d %s\n\n",
	       SegDef.ppNextSeg, SegDef.cSymbols, SegDef.pSymDef, SegDef.wSegNum,
	       SegDef.wInstance0, SegDef.wInstance1, SegDef.wInstance2,
	       SegDef.bFlags,
	       SegDef.bFlags&0x01 ? "32-bit" : "16-bit",
	       SegDef.bReserved1,
	       SegDef.ppLineDef, SegDef.bIsSegLoaded, SegDef.bCurrInstance,
	       SegDef.cbSegName, Buffer);
#	endif

	/* 06 May 08 SHL Add large .sym file support
	   Symbol table format uses 16-bit offsets to point at the symbol
	   pointer table and to point at SymDef entries.  This breaks if there
	   are more than approx 64KiB of SymDefs.  To workaround this,
	   we assume that the symbol pointer table ends at the next SegDef
	   or at the end of file.  We then use the difference between the
	   calculated offset of the end of the pointer table and the calculated
	   offset to the next SegDef to calculate an adjusting offset.
	   This offset is applied to symbol pointer table lookups.
	   We also assume that the SymDef offsets in the symbol pointer table
	   are monotonic and detect 64KiB boundary crossings to calculate an
	   adjusting offset.  This offset is applied to SymDef entry indexing.
	*/
	// Calc location following symbol pointer table based on values
	ulSymPtrOffset=SYMDEFOFFSET(ulSegOffset,SegDef,SegDef.cSymbols);
	// Calc location of next segment
	if (usSegNum + 1 == MapDef.cSegs) {
	   fseek(fpSymFile,0,SEEK_END);
	   ulNextSegOffset = ftell(fpSymFile);
	}
	else
	   ulNextSegOffset=NEXTSEGDEFOFFSET(SegDef);
	// Calc offset error in 64K blocks
	ulSymPtrAdjust = (ulNextSegOffset - ulSymPtrOffset) / 0x10000;
	// Calc offset adjust - will be 0 for normal files
	ulSymPtrAdjust *= 0x10000;

#	ifdef DBGLRG
	if (ulSymPtrAdjust)
	   printf("Adjusting pSymDef by 0x%lx for large file\n\n",ulSymPtrAdjust);
#	endif

	usSymOffset = 0;
	ulSymOffsetAdjust = 0;

	for (usSymNum=0;usSymNum<SegDef.cSymbols;usSymNum++) {
	   ulSymPtrOffset=SYMDEFOFFSET(ulSegOffset,SegDef,usSymNum);
	   ulSymPtrOffset += ulSymPtrAdjust;	// 06 May 08 SHL Adjust for large files
#	   ifdef DBGLRG
	   printf("ulSymPtrOffset 0x%08X Sym #%d",ulSymPtrOffset,usSymNum+1);
#	   endif
	   fseek(fpSymFile,ulSymPtrOffset,SEEK_SET);
	   usLastSymOffset = usSymOffset;
	   fread(&usSymOffset,sizeof(unsigned short int),1,fpSymFile);
#	   ifdef DBGLRG
	   printf(" usSymOffset 0x%X\n",usSymOffset);
#	   endif
	   // If symbol entries crossed 64K boundary, bump adjusting offset
	   if (usSymOffset < usLastSymOffset) {
	       ulSymOffsetAdjust += 0x10000;
#	       ifdef DBGLRG
	       printf("                  Adjusting usSymOffset by 0x%lx for large file\n",ulSymOffsetAdjust);
#	       endif
	   }
#	   ifdef DBGLRG
	   printf("SymDef at 0x%08X",usSymOffset+ulSegOffset+ulSymOffsetAdjust);
#	   endif
	   fseek(fpSymFile,usSymOffset+ulSegOffset+ulSymOffsetAdjust,SEEK_SET);

	   if (SegDef.bFlags&0x01) {
	      // 32-bit symbol
	      fread(&SymDef32,sizeof(SYMDEF32),1,fpSymFile);
	      Buffer[0]= SymDef32.achSymName[0];
	      fread(&Buffer[1],1,SymDef32.cbSymName,fpSymFile);
	      Buffer[SymDef32.cbSymName]=0;
	      printf(" 32 Bit Symbol <%s> Address %x:%x\n",
		     Buffer, usSegNum + 1, SymDef32.wSymVal);
	   } else {
	      // 16-bit symbol
	      fread(&SymDef16,sizeof(SYMDEF16),1,fpSymFile);
	      Buffer[0]=SymDef16.achSymName[0];
	      fread(&Buffer[1],1,SymDef16.cbSymName,fpSymFile);
	      Buffer[SymDef16.cbSymName]=0;
	      printf(" 16 Bit Symbol <%s> Address %x:%x\n",
		     Buffer, usSegNum + 1, SymDef16.wSymVal);
	   } /* endif */

	} // for usSymNum

	ulSegOffset=NEXTSEGDEFOFFSET(SegDef);
   } /* for usSegNum */

   fclose(fpSymFile);
   return 0;

} // main

// The end
