/*********************************************************************
  hlldbg.h - HLL Debug Data Format data structures
  $Id: hlldbg.h,v 1.1 2009/02/24 20:37:29 Steven Exp $

  Debug info definitions apply to IBM HLL (NB04) debug data
  and Microsoft CodeView (NB02?) format

  27 May 08 SHL Split form omf.h, build from exceptq.c
*/

#ifndef HLLDBG_H
#define HLLDBG_H

#pragma pack(1)

//=== HLL/CodeView debug info ===
// see ow\bld\watcom\h\hll.h

/* Known formats

   NB00	Microsoft 32-bit CodeView
   NB01	Microsoft AIX symbol
   NB02		Microsoft 16-bit CodeView, aka pre-CV4, Microsoft Link v5.1 IBM C v6.0?
   NB03		IBM HLL CSet/2
   NB04		32-bit OS/2 Program Manager, aka IBM HLL, VAC 3.x
   NB05		CodeView V4, Microsoft Link v5.20+
   NB06	Microsoft packed
   NB07	Microsoft, Quick C for Windows 1.0 only
   NB08	Microsoft CodeView packed?, debugger versions 4.00 through 4.05
   NB09		CodeView V4 cvpack'ed, Microsoft CodeView v4.10+

*/

#define HLLDBG_SIG 0x424E		/* "NB" IBM HLL signature */

/* Last 8 bytes of when OMF style debugging info is present
 * Used for Codeview and VAC HLL and BC OA debug data
 * signature is FB for BC OA debug
 */

// Debug info header - first 8 bytes of debug data
typedef struct
{
   USHORT signature;                  // Debug signature 'NB' or 'FB'
   USHORT version;                    // Debug info type '00' '01' '04' ...
   ULONG lfoDir;		      // offset to directory entries from debug_head_rec
} debug_head_rec;

// Debug info trailer - - last 8 bytes of debug data/data
typedef struct
{
   USHORT signature;                  // Debug signature 'NB' or 'FB'
   USHORT version;                    // Debug info type '00' '01' '04' ...
   ULONG offset;                      // Offset to dir_info_rec from end of file
} debug_tail_rec;

// ss = Subsection

/* HLL subsection directory header - NB04 */
typedef struct
{
    USHORT cbDirHeader;			// Header size in bytes - fixme to verify
    USHORT cbDirEntry;			// Directory entry size in bytes
    ULONG cDir;				// Directory entry count
   // Array of ssDir32 directory subsection descriptors follow
} hll_dirinfo;

// CV3 debug subsection (ss) directory info header - NB02?
// fixme to verify
typedef struct
{
   USHORT   dirstruct_size;            // Size of directory structure
   USHORT   number_of_entries;         // Number of dnt_rec's in the array
   USHORT   unknown;                   // Unknown data
   // Array of ssDir directory subsection descriptors follow
} cv_dirinf_rec;

/* CV3 subsection directory header - fixme */
typedef struct
{
    USHORT cDir;
} cv3_dirinfo;

/* CV3 debug subsection (ss) directory info header - NB02 */
typedef struct
{
    USHORT cbDirHeader;			// Header size
    USHORT cbDirEntry;			// Directory entry size
    ULONG cDir;				// Number of directory entries
} cv3_dirinfo_rec;

// sst definitions
#define         SSTMODULES      0x0101	/* Modules */
#define         SSTPUBLICS      0x0102	/* Public symbols */
#define         SSTTYPES        0x0103	/* Types */
#define         SSTSYMBOLS      0x0104	/* Symbols */
#define         SSTSRCLINES     0x0105	/* Line numbers - (IBM C/2 1.1) */
#define         SSTLIBRARIES    0x0106	/* Libraries */
#define         SSTSRCLINES2    0x0109	/* Line numbers - (MSC 6.00) */
#define         SSTSRCLINES32   0x010B	/* Line numbers - (IBM HLL) */

// HLL Directory subsection descriptor
typedef struct
{
    USHORT sst;		/* SubSection Type */
    USHORT modindex;	/* Module index number */
    ULONG lfoStart;	/* Start of section */
    ULONG cb;		/* Size of section */
} ssDir32;

// Codeview 16 directory subsection descriptor
typedef struct
{
    USHORT sst;		/* SubSection Type */
    USHORT modindex;	/* Module index number */
    ULONG lfoStart;	/* Start of section */
    USHORT cb;		/* Size of section */
} ssDir16;

// 16-bit Module subsection header (SSTMODULES)
typedef struct
{
    USHORT csBase;	/* code segment base */
    USHORT csOff;	/* code segment offset */
    USHORT csLen;	/* code segment length */
    USHORT ovrNum;	/* overlay number */
    USHORT indxSS;	/* Index into sstLib or 0 */
    USHORT reserved;
    CHAR csize;		/* size of prefix string */
} ssModule;

// 32-bit Module subsection header (SSTMODULES)
typedef struct
{
    USHORT csBase;	/* code segment base */
    ULONG csOff;	/* code segment offset */
    ULONG csLen;	/* code segment length */
    ULONG ovrNum;	/* overlay number */
    USHORT indxSS;	/* Index into sstLib or 0 */
    ULONG reserved;
    CHAR csize;			/* size of prefix string */
} ssModule32;

// 30 May 08 SHL fixme to know what this is
// Module subsection header (SSTMODULES)
typedef struct
{
   USHORT   code_seg_base;             // Code segment base
   ULONG    code_seg_offset;           // Code segment offset
   ULONG    code_seg_len;              // Code segment length
   USHORT   overlay_no;                // Overlay number
   USHORT   lib_idx;                   // Index into library section or 0
   BYTE     segments;                  // Number of segments
   BYTE     reserved;
   BYTE     debug_style[2];            // "HL" for HLL, "CV" or 0 for CodeView
   BYTE     debug_version[2];          // 00 01 or 00 03 for HLL, 00 00 for CV
   BYTE     name_len;                  // Length of name (which follows)
} modules_rec;


// SSTPUBLICS - CodeView
typedef struct
{
    USHORT offset;
    USHORT segment;
    USHORT type;
    CHAR csize;
} ssPublic;

// SSTPUBLICS - HLL
typedef struct
{
    ULONG offset;
    USHORT segment;
    USHORT type;
    CHAR csize;                  // Length of name (which follows)
} ssPublic32;


// ssFirstLineEntry32.entry_type values
#define LINEREC_SRC_LINES	0	// Source line numbers
#define LINEREC_LIST_LINES	1	// Listing lines numbers
#define LINEREC_SRCLIST_LINES	2	// Combo source and listing line numbers
#define LINEREC_FILENAMES	3	// Filenames list
#define LINEREC_PATHINFO	4	// path info

// First linenumber record (special)
typedef struct
{
    USHORT LineNum;
    UCHAR entry_type;
    UCHAR reserved;
    USHORT numlines;
    USHORT usSegNum;
} ssFirstLineEntry32;

typedef struct
{
    USHORT LineNum;
    USHORT FileNum;
    ULONG ulOffset;
} ssLineEntry32;

typedef struct
{
    ULONG first_displayable;		/* Not used */
    ULONG number_displayable;		/* Not used */
    ULONG file_count;			/* number of source files */
} ssFileNum32;

// Listing statement numbers - LINEREC_LIST_LINES
typedef struct
{
   ULONG    list_line;                 // Listing file line number
   ULONG    statement;                 // Listing file statement number
   ULONG    offset;                    // Offset into segment
} linlist_rec;

// Source and Listing statement numbers - LINEREC_SRCLIST_LINES
typedef struct
{
   USHORT   source_line;               // Source file line number
   USHORT   source_idx;                // Source file index
   ULONG    list_line;                 // Listing file linenumber
   ULONG    statement;                 // Listing file statement number
   ULONG    offset;                    // Offset into segment
} linsourcelist_rec;

// Path table - LINEREC_PATH
typedef struct
{
   ULONG    offset;                    // Offset into segment
   USHORT   path_code;                 // Path code
   USHORT   source_idx;                // Source file index
} pathtab_rec;

// File names table - LINEREC_FILENAMES - must be 1st linenumbers record
typedef struct
{
   ULONG    first_char;                // First displayable char in list file
   ULONG    disp_chars;                // Number of displayable chars in list line
   ULONG    filecount;                 // Number of source/listing files
				       // names follow prefixed by 1 bytes length
} filenam_rec;

// Symbol types
#define SYM_BEGIN          0x00        // Begin block
#define SYM_PROC           0x01        // Function
#define SYM_END            0x02        // End block of function
#define SYM_AUTO           0x04        // Auto variable
#define SYM_STATIC         0x05        // Static variable
#define SYM_LABEL          0x0B        // Label
#define SYM_WITH           0x0C        // With start symbol (not used)
#define SYM_REG            0x0D        // Register variable
#define SYM_CONST          0x0E        // Constant
#define SYM_ENTRY          0x0F        // Secondary entry (not in C)
#define SYM_SKIP           0x10        // For incremental linking (not used)
#define SYM_CHANGESEG      0x11        // Change segment (#pragma alloc_text)
#define SYM_TYPEDEF        0x12        // Typedef variable
#define SYM_PUBLIC         0x13        // Public reference
#define SYM_MEMBER         0x14        // Member of minor or major structure
#define SYM_BASED          0x15        // Based variable
#define SYM_TAG            0x16        // Tag in struct, union, enum ...
#define SYM_TABLE          0x17        // Table (used in RPG - not C)
#define SYM_MAP            0x18        // Map variable (extern in C)
#define SYM_CLASS          0x19        // Class symbol (C++)
#define SYM_MEMFUNC        0x1A        // Member function
#define SYM_AUTOSCOPE      0x1B        // Scoped auto for C++ (not used)
#define SYM_STATICSCOPE    0x1C        // scoped static for C++ (not used)
#define SYM_CPPPROC        0x1D        // C++ Proc
#define SYM_CPPSTAT        0x1E        // C++ Static var
#define SYM_COMP           0x40        // Compiler information

// Symbolic begin record
typedef struct
{
   ULONG    offset;                    // Segment offset
   ULONG    length;                    // Length of block
   BYTE     name_len;                  // Length of block name
   // Block name follows
} symbegin_rec;

// Symbolic auto var record
typedef struct
{
   ULONG    stack_offset;              // Stack offset
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Var name follows
} symauto_rec;

// Symbolic procedure record
typedef struct
{
   ULONG    offset;                    // Segment offset
   USHORT   type_idx;                  // Type index
   ULONG    length;                    // Length of procedure
   USHORT   pro_len;                   // Length of prologue
   ULONG    pro_bodylen;               // Length of prologue + body
   USHORT   class_type;                // Class type
   BYTE     near_far;                  // Near or far
   BYTE     name_len;                  // Length of name
   // Function name follows
} symproc_rec;

// Symbolic static var record
typedef struct
{
   ULONG    offset;                    // Segment offset
   USHORT   segaddr;                   // Segment address
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Var name follows
} symstatic_rec;

// Symbolic label var record
typedef struct
{
   ULONG    offset;                    // Segment offset
   BYTE     near_far;                  // Near or far
   BYTE     name_len;                  // Length of name
   // Var name follows
} symlabel_rec;

// Symbolic register var record
typedef struct
{
   USHORT   type_idx;                  // Type index
   BYTE     reg_no;                    // Register number
   BYTE     name_len;                  // Length of name
   // Var name follows
} symreg_rec;

// Symbolic change-segment record
typedef struct
{
   USHORT   seg_no;                    // Segment number
} symseg_rec;

// Symbolic typedef record
typedef struct
{
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
} symtypedef_rec;

// Symbolic public record
typedef struct
{
   ULONG    offset;                    // Segment offset
   USHORT   segaddr;                   // Segment address
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
} sympublic_rec;

// Symbolic member record
typedef struct
{
   ULONG    offset;                    // Offset to subrecord
   BYTE     name_len;                  // Length of name
   // Name follows
} symmember_rec;

// Symbolic based record
typedef struct
{
   ULONG    offset;                    // Offset to subrecord
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
} symbased_rec;

// Symbolic tag record
typedef struct
{
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
} symtag_rec;

// Symbolic table record
typedef struct
{
   ULONG    offset;                    // Segment offset
   USHORT   segaddr;                   // Segment address
   USHORT   type_idx;                  // Type index
   ULONG    idx_ofs;                   // Index offset to subrecord
   BYTE     name_len;                  // Length of name
   // Name follows
} symtable_rec;

// Type record
typedef struct
{
   USHORT   length;                    // Length of sub-record
   BYTE     type;                      // Sub-record type
   BYTE     type_qual;                 // Type qualifier
} type_rec;

// Types
#define TYPE_CLASS         0x40        // Class
#define TYPE_BASECLASS     0x41        // Base class
#define TYPE_FRIEND        0x42        // Friend
#define TYPE_CLASSDEF      0x43        // Class definition
#define TYPE_MEMBERFUNC    0x45        // Member function
#define TYPE_CLASSMEMBER   0x46        // Class member
#define TYPE_REF           0x48        // Reference
#define TYPE_MEMBERPTR     0x49        // Member pointer
#define TYPE_SCALARS       0x51        // Scalars
#define TYPE_SET           0x52        // Set
#define TYPE_ENTRY         0x53        // Entry
#define TYPE_FUNCTION      0x54        // Function
#define TYPE_AREA          0x55        // Area
#define TYPE_LOGICAL       0x56        // Logical
#define TYPE_STACK         0x57        // Stack
#define TYPE_MACRO         0x59        // Macro
#define TYPE_BITSTRING     0x5C        // Bit string
#define TYPE_USERDEF       0x5D        // User defined
#define TYPE_CHARSTR       0x60        // Character string
#define TYPE_PICTURE       0x61        // Picture
#define TYPE_GRAPHIC       0x62        // Graphic
#define TYPE_FORMATLAB     0x65        // Format label
#define TYPE_FILE          0x67        // File
#define TYPE_SUBRANGE      0x6F        // Subrange
#define TYPE_CODELABEL     0x72        // Code label
#define TYPE_PROCEDURE     0x75        // Procedure
#define TYPE_ARRAY         0x78        // Array
#define TYPE_STRUCT        0x79        // Structure / Union / Record
#define TYPE_POINTER       0x7A        // Pointer
#define TYPE_ENUM          0x7B        // Enum
#define TYPE_LIST          0x7F        // List

/* Unnamed primitive types
   28 May 08 SHL fixme to have names

   DEC       HEX          DESCRIPTION
  =====     =====       ===============

   128        80          8 bit signed
   129        81          16 bit signed
   130        82          32 bit signed
   132        84          8 bit unsigned
   133        85          16 bit unsigned
   134        86          32 bit unsigned
   136        88          32 bit real
   137        89          64 bit real
   138        8A          80 bit real
   140        8C          64 bit complex
   141        8D	  128 bit complex
   142        8E          160 bit complex
   144        90          8 bit boolean
   145        91          16 bit boolean
   146        92          32 bit boolean
   148        94          8 bit character
   149        95          16 bit characters
   150        96          32 bit characters
   151        97          void
   152        98          15 bit unsigned
   153        99          24 bit unsigned
   154        9A          31 bit unsigned
   155        9B          64 bit signed (long_long)
   156        9C          64 bit unsigned
   160        A0          near pointer to 8 bit signed
   161        A1          near pointer to 16 bit signed
   162        A2          near pointer to 32 bit signed
   164        A4          near pointer to 8 bit unsigned
   165        A5          near pointer to 16 bit unsigned
   166        A6          near pointer to 32 bit unsigned
   168        A8          near pointer to 32 bit real
   169        A9          near pointer to 64 bit real
   170        AA          near pointer to 80 bit real
   172        AC          near pointer to 64 bit complex
   173        AD          near pointer to 128 bit complex
   174        AE          near pointer to 160 bit complex
   176        B0          near pointer to 8 bit boolean
   177        B1          near pointer to 16 bit boolean
   178        B2          near pointer to 32 bit boolean
   180        B4          near pointer to 8 bit character
   181        B5          near pointer to 16 bit character
   182        B6          near pointer to 32 bit character
   183        B7          near pointer to void
   184        B8          near pointer to 15 bit unsigned
   185        B9          near pointer to 24 bit unsigned
   186        BA          near pointer to 31 bit unsigned
   187        BB          near pointer to 64 bit signed
   188        BC          near pointer to 64 bit unsigned

   DEC       HEX          DESCRIPTION
  =====     =====       ===============

   192        C0          far pointer to 8 bit signed
   193        C1          far pointer to 16 bit signed
   194        C2          far pointer to 32 bit signed
   196        C4          far pointer to 8 bit unsigned
   197        C5          far pointer to 16 bit unsigned
   198        C6          far pointer to 32 bit unsigned
   200        C8          far pointer to 32 bit real
   201        C9          far pointer to 64 bit real
   202        CA          far pointer to 80 bit real
   204        CC          far pointer to 64 bit complex
   205        CD          far pointer to 128 bit complex
   206        CE          far pointer to 160 bit complex
   208        D0          far pointer to 8 bit boolean
   209        D1          far pointer to 16 bit boolean
   210        D2          far pointer to 32 bit boolean
   212        D4          far pointer to 8 bit character
   213        D5          far pointer to 16 bit character
   214        D6          far pointer to 32 bit character
   215        D7          far pointer to void
   216        D8          far pointer to 15 bit unsigned
   217        D9          far pointer to 24 bit unsigned
   218        DA          far pointer to 31 bit unsigned
   219        DB          far pointer to 64 bit signed
   220        DC          far pointer to 64 bit unsigned

*/

// Type userdef
typedef struct
{
   BYTE     FID_index;                 // Field ID
   USHORT   type_index;                // Type index
   BYTE     FID_string;                // String ID
   BYTE     name_len;                  // Length of name which follows
} type_userdefrec;

// Type function
typedef struct
{
   USHORT   params;
   USHORT   max_params;
   BYTE     FID_index;                 // Field ID
   USHORT   type_index;                // Type index of return value
   BYTE     FID_index1;                // String ID
   USHORT   typelist_index;            // Index of list of params
} type_funcrec;

// Type struct
typedef struct
{
   ULONG    size;                      // Size of structure
   USHORT   field_count;               // Number of fields in structure
   BYTE     FID_index;                 // Field ID
   USHORT   type_list_idx;             // Index to type list
   BYTE     FID_index1;                // Field ID
   USHORT   type_name_idx;             // Index to names / offsets
   BYTE     dont_know;                 // Haven't a clue, but it seems to be needed
   BYTE     name_len;                  // Length of structure name which follows
} type_structrec;

// Type list, type qualifier 1: contains types for structures
// This record is repeated for the number of items in the structure definition
typedef struct
{
   BYTE     FID_index;                 // Field identifier for index
   USHORT   type_index;                // Type index.
} type_list1;

// Type list, type qualifier 2: contains names and offsets for structure items
// This record is repeated for the number of items in the structure definition
typedef struct
{
   BYTE     FID_string;                // String identifier
   BYTE     name_len;                  // Length of name which follows
} type_list2;

// Type list, subrecord to the above, contains offset of variable in the structure
typedef struct
{
   BYTE     FID_span;                  // Defines what type of variable follows
   union {
      BYTE   b_len;
      USHORT s_len;
      ULONG  l_len;
   } u;
} type_list2_1;

// Type pointer
typedef struct
{
   BYTE     FID_index;                 // Index identifier
   USHORT   type_index;                // Type index
   BYTE     FID_string;                // String identifier
   BYTE     name_len;                  // Length of name which follows
} type_pointerrec;

#pragma pack()

#endif // HLLDBG_H
