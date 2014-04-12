/*********************************************************************
  omf.h - OMF Object Module Format data structures
  $Id: omf.h,v 1.3 2008/05/24 23:24:19 Steven Exp $

  Debug info definitions apply to IBM and BC HLL debug format

  03 Aug 05 SHL Restore default packing
  22 May 08 SHL Correct debug_head_rec
  22 May 08 SHL Localize more here
*/

#pragma pack(1)

// MZ executable header

struct exehdr_rec {
   BYTE     signature[2];              // Must be "MZ"
   USHORT   image_len;                 // Image Length
   USHORT   pages;                     // Pages
   USHORT   reloc_items;               // Relocation table items
   USHORT   min_paragraphs;            // Mininum 16-bytes paragraphs
   USHORT   max_paragraphs;            // Maximum 16-bytes paragraphs
   USHORT   stack_pos;                 // Stack position
   USHORT   offset_in_sp;              // Offset in SP
   USHORT   checksum;                  // Checksum
   USHORT   offset_in_ip;              // Offset in IP
   USHORT   code_pos;                  // Code segment pos.
   USHORT   reloc_item_pos;            // Position of first relocation item
   USHORT   overlay_number;            // Overlay number
   BYTE     unused[8];                 // Unused bytes
   USHORT   oem_id;                    // OEM Identifier
   BYTE     oem_info[24];              // OEM Info
   ULONG    lexe_offset;               // Offset to linear header
};

// LX executable header

struct lexehdr_rec {
   BYTE     signature[2];              // Must be "LX"
   BYTE     b_ord;                     // Byte ordering
   BYTE     w_ord;                     // Word ordering
   ULONG    format_level;              // Format level
   USHORT   cpu_type;                  // CPU Type
   USHORT   os_type;                   // Operating system
   ULONG    module_version;            // Module version
   ULONG    mod_flags;                 // Module flags
   ULONG    mod_pages;                 // Module pages
   ULONG    EIP_object;                // EIP Object no.
   ULONG    EIP;                       // EIP Value
   ULONG    ESP_object;                // ESP Object no
   ULONG    ESP;                       // ESP Value
   ULONG    page_size;                 // Page size
   ULONG    page_ofs_shift;            // Page offset shift
   ULONG    fixup_sect_size;           // Fixup section size
   ULONG    fixup_sect_checksum;       // Fixup section checksum
   ULONG    loader_sect_size;          // Loader section size
   ULONG    loader_sect_checksum;      // Loader section checksum
   ULONG    obj_table_ofs;             // Object table offset
   ULONG    obj_count;                 // Object count
   ULONG    obj_page_tab_ofs;          // Object page table offset
   ULONG    obj_iter_page_ofs;         // Object iteration pages offset
   ULONG    res_tab_ofs;               // Resource table offset
   ULONG    res_table_entries;         // Resource table entries
   ULONG    res_name_tab_ofs;          // Resident name table offset;
   ULONG    ent_tab_ofs;               // Entry table offset
   ULONG    mod_dir_ofs;               // Module directives offset
   ULONG    mod_dir_count;             // Number of module directives
   ULONG    fixup_page_tab_ofs;        // Fixup page table offset
   ULONG    fixup_rec_tab_ofs;         // Fixup record table offset
   ULONG    imp_tab_ofs;               // Import module table offset
   ULONG    imp_mod_entries;           // Import module entries
   ULONG    imp_proc_tab_ofs;          // Import proc table offset
   ULONG    per_page_check_ofs;        // Per page checksum offset
   ULONG    data_page_offset;          // Data pages offset
   ULONG    preload_page_count;        // Preload pages count
   ULONG    nonres_tab_ofs;            // Nonresident name table offset
   ULONG    nonres_tab_len;            // Nonresident name table len
   ULONG    nonres_tab_check;          // Nonresident tables checksum
   ULONG    auto_ds_objectno;          // Auto DS object number
   ULONG    debug_info_ofs;            // Debug info offset
   ULONG    debug_info_len;            // Debug info length
   ULONG    inst_preload_count;        // Instance preload count
   ULONG    inst_demand_count;         // Instance demand count
   ULONG    heapsize;                  // Heap size
   ULONG    stacksize;                 // Stack size
};

//=== OMF HLL debug info ===

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

   FB09		Borland Open Architecture BC2.0 OS/2
*/

#define         DBUGSIG         0x424E	/* "NB" IBM HLL signature */
#define         BCSIG           0x4246	/* "FB" Borland OA signature */

// Debug info header

struct debug_head_rec {
   USHORT signature;                  // Debug signature 'NB' or 'FB'
   USHORT version;                    // Debug info type '00' '01' '04' ...
   ULONG lfoDir;		      // offset to directory entries from debug_head_rec
};

// Debug info tail record - last 8 bytes of file/data
// ss = Subsection

struct debug_tail_rec {
   USHORT signature;                  // Debug signature 'NB' or 'FB'
   USHORT version;                    // Debug info type '00' '01' '04' ...
   ULONG offset;                      // Offset to dir_info_rec from end of file
};

// CV3 debug subsection (ss) directory info header - NB02?

struct cv_dirinf_rec {
   USHORT   dirstruct_size;            // Size of directory structure
   USHORT   number_of_entries;         // Number of dnt_rec's in the array
   USHORT   unknown;                   // Unknown data
   // Array of dnt_rec structures follows
};

/* HLL debug subsection (ss) directory info header - NB04 */
struct hll_dirinfo_rec {
    USHORT cbDirHeader;			// Header size
    USHORT cbDirEntry;			// Directory entry size
    ULONG cDir;				// Number of directory entries
};


// subsect_type definitions
#define         SSTMODULES      0x0101	/* Modules */
#define         SSTPUBLICS      0x0102	/* Public symbols */
#define         SSTTYPES        0x0103	/* Types */
#define         SSTSYMBOLS      0x0104	/* Symbols */
#define         SSTSRCLINES     0x0105	/* Line numbers - (IBM C/2 1.1) */
#define         SSTLIBRARIES    0x0106	/* Libraries */
#define         SSTSRCLINES2    0x0109	/* Line numbers - (MSC 6.00) */
#define         SSTSRCLINES32   0x010B	/* Line numbers - (IBM HLL) */

// Directory subsection descriptor
struct hll_dir_entry {
   USHORT   subsect_type;              // sst Subsection type
   USHORT   mod_index;                 // Module index (1-based)
   ULONG    offset;                    // Offset of start of section from start of data
   ULONG    size;                      // Size of section
};

// Module subsection header (SSTMODULES)
struct modules_rec {
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
};

// Publics subsection (SSTPUBLICS)
struct publics_rec {
   ULONG    offset;                    // Offset
   USHORT   segment;                   // Segment
   USHORT   type;                      // Type index
   BYTE     name_len;                  // Length of name (wich follows)
};

#if 0
// Linenumbers header
struct linhead_rec {
   BYTE     id;                        // 0x95 for flat mem, 32 bit progs
   USHORT   length;                    // Record length
   USHORT   base_group;                // Base group
   USHORT   base_segment;              // Base segment
};
#endif

// First linenumber record (special)

// entry_type values
#define LINEREC_SRC_LINES	0	// Source line numbers
#define LINEREC_LIST_LINES	1	// Listing lines numbers
#define LINEREC_SRCLIST_LINES	2	// Combo source and listing line numbers
#define LINEREC_FILENAMES	3	// Filenames list
#define LINEREC_PATHINFO	4	// path info

struct linfirst_rec {
   USHORT   lineno;                    // Line number (0)
   BYTE     entry_type;                // Entry type
   BYTE     reserved;                  // Reserved
   USHORT   entries_count;             // Number of table entries
   USHORT   segment_no;                // Segment number
   union {
     ULONG    seg_address;             // Logical Segment address - type 0, 1, 2
     ULONG    length;		       // record length in bytes - type 3
   } u;				       // omitted for type 4
				       // line records follow
};

// Source line numbers - LINEREC_SRC_LINES
struct linsource_rec {
   USHORT   source_line;               // Source file line number
   USHORT   source_idx;                // Source file index (1..n)
   ULONG    offset;                    // Offset into segment
};

// Listing statement numbers - LINEREC_LIST_LINES
struct linlist_rec {
   ULONG    list_line;                 // Listing file line number
   ULONG    statement;                 // Listing file statement number
   ULONG    offset;                    // Offset into segment
};

// Source and Listing statement numbers - LINEREC_SRCLIST_LINES
struct linsourcelist_rec {
   USHORT   source_line;               // Source file line number
   USHORT   source_idx;                // Source file index
   ULONG    list_line;                 // Listing file linenumber
   ULONG    statement;                 // Listing file statement number
   ULONG    offset;                    // Offset into segment
};

// Path table - LINEREC_PATH
struct pathtab_rec {
   ULONG    offset;                    // Offset into segment
   USHORT   path_code;                 // Path code
   USHORT   source_idx;                // Source file index
};

// File names table - LINEREC_FILENAMES - must be 1st linenumbers record
struct filenam_rec {
   ULONG    first_char;                // First displayable char in list file
   ULONG    disp_chars;                // Number of displayable chars in list line
   ULONG    filecount;                 // Number of source/listing files
				       // names follow prefixed by 1 bytes length
};

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
struct symbegin_rec {
   ULONG    offset;                    // Segment offset
   ULONG    length;                    // Length of block
   BYTE     name_len;                  // Length of block name
   // Block name follows
};

// Symbolic auto var record
struct symauto_rec {
   ULONG    stack_offset;              // Stack offset
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Var name follows
};

// Symbolic procedure record
struct symproc_rec {
   ULONG    offset;                    // Segment offset
   USHORT   type_idx;                  // Type index
   ULONG    length;                    // Length of procedure
   USHORT   pro_len;                   // Length of prologue
   ULONG    pro_bodylen;               // Length of prologue + body
   USHORT   class_type;                // Class type
   BYTE     near_far;                  // Near or far
   BYTE     name_len;                  // Length of name
   // Function name follows
};

// Symbolic static var record
struct symstatic_rec {
   ULONG    offset;                    // Segment offset
   USHORT   segaddr;                   // Segment address
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Var name follows
};

// Symbolic label var record
struct symlabel_rec {
   ULONG    offset;                    // Segment offset
   BYTE     near_far;                  // Near or far
   BYTE     name_len;                  // Length of name
   // Var name follows
};

// Symbolic register var record
struct symreg_rec {
   USHORT   type_idx;                  // Type index
   BYTE     reg_no;                    // Register number
   BYTE     name_len;                  // Length of name
   // Var name follows
};

// Symbolic change-segment record
struct symseg_rec {
   USHORT   seg_no;                    // Segment number
};

// Symbolic typedef record
struct symtypedef_rec {
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
};

// Symbolic public record
struct sympublic_rec {
   ULONG    offset;                    // Segment offset
   USHORT   segaddr;                   // Segment address
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
};

// Symbolic member record
struct symmember_rec {
   ULONG    offset;                    // Offset to subrecord
   BYTE     name_len;                  // Length of name
   // Name follows
};

// Symbolic based record
struct symbased_rec {
   ULONG    offset;                    // Offset to subrecord
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
};

// Symbolic tag record
struct symtag_rec {
   USHORT   type_idx;                  // Type index
   BYTE     name_len;                  // Length of name
   // Name follows
};

// Symbolic table record
struct symtable_rec {
   ULONG    offset;                    // Segment offset
   USHORT   segaddr;                   // Segment address
   USHORT   type_idx;                  // Type index
   ULONG    idx_ofs;                   // Index offset to subrecord
   BYTE     name_len;                  // Length of name
   // Name follows
};

// Type record
struct type_rec {
   USHORT   length;                    // Length of sub-record
   BYTE     type;                      // Sub-record type
   BYTE     type_qual;                 // Type qualifier
};

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

// Type userdef
struct type_userdefrec {
   BYTE     FID_index;                 // Field ID
   USHORT   type_index;                // Type index
   BYTE     FID_string;                // String ID
   BYTE     name_len;                  // Length of name which follows
};

// Type function
struct type_funcrec {
   USHORT   params;
   USHORT   max_params;
   BYTE     FID_index;                 // Field ID
   USHORT   type_index;                // Type index of return value
   BYTE     FID_index1;                // String ID
   USHORT   typelist_index;            // Index of list of params
};

// Type struct
struct type_structrec {
   ULONG    size;                      // Size of structure
   USHORT   field_count;               // Number of fields in structure
   BYTE     FID_index;                 // Field ID
   USHORT   type_list_idx;             // Index to type list
   BYTE     FID_index1;                // Field ID
   USHORT   type_name_idx;             // Index to names / offsets
   BYTE     dont_know;                 // Haven't a clue, but it seems to be needed
   BYTE     name_len;                  // Length of structure name which follows
};

// Type list, type qualifier 1: contains types for structures
// This record is repeated for the number of items in the structure definition
struct type_list1 {
   BYTE     FID_index;                 // Field identifier for index
   USHORT   type_index;                // Type index.
};

// Type list, type qualifier 2: contains names and offsets for structure items
// This record is repeated for the number of items in the structure definition
struct type_list2 {
   BYTE     FID_string;                // String identifier
   BYTE     name_len;                  // Length of name which follows
};

// Type list, subrecord to the above, contains offset of variable in the structure
struct type_list2_1 {
   BYTE     FID_span;                  // Defines what type of variable follows
   union {
      BYTE   b_len;
      USHORT s_len;
      ULONG  l_len;
   } u;
};

// Type pointer
struct type_pointerrec {
   BYTE     FID_index;                 // Index identifier
   USHORT   type_index;                // Type index
   BYTE     FID_string;                // String identifier
   BYTE     name_len;                  // Length of name which follows
};

#pragma pack()

// The end
