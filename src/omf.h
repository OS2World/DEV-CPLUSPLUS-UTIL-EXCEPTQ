/*********************************************************************
  omf.h - IBM Linear Executable (LX) and Object Module Format (OMF) data structures
  $Id: omf.h,v 1.4 2009/02/24 20:37:43 Steven Exp $

  See lxomf.pdf for details

  03 Aug 05 SHL Restore default packing
  22 May 08 SHL Correct debug_head_rec
  22 May 08 SHL Localize more here
  27 May 08 SHL Split HLL data to hlldbg.h
  
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

// OMF debug data???

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

struct publics_rec {
   ULONG    offset;                    // Offset
   USHORT   segment;                   // Segment
   USHORT   type;                      // Type index
   BYTE     name_len;                  // Length of name (wich follows)
};

// Linenumbers header
struct linhead_rec {
   BYTE     id;                        // 0x95 for flat mem, 32 bit progs
   USHORT   length;                    // Record length
   USHORT   base_group;                // Base group
   USHORT   base_segment;              // Base segment
};

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

// Source line numbers
struct linsource_rec {
   USHORT   source_line;               // Source file line number
   USHORT   source_idx;                // Source file index (1..n)
   ULONG    offset;                    // Offset into segment
};

#pragma pack()

// The end
