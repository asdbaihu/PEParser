// GENERAL TYPES

typedef unsigned char		BYTE;	// 1 byte
typedef unsigned short		WORD;	// 2 bytes
typedef unsigned int		DWORD;	// 4 bytes
typedef  long				LONG;	// 4 bytes

// DOS HEADER STRUCTURE

#define IMAGE_DOS_SIGNATURE                 0x4D5A      // MZ


typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// PE HEADER STRUCTURES

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;					// The architecture type of the computer
  WORD  NumberOfSections;			// The number of sections. This indicates the size of the section table, which immediately follows the headers.
  DWORD TimeDateStamp;				// The low 32 bits of the time stamp of the image. This represents the date and time the image was created by the linker
  DWORD PointerToSymbolTable;		// The offset of the symbol table, in bytes, or zero if no COFF symbol table exists
  DWORD NumberOfSymbols;			// The number of symbols in the symbol table
  WORD  SizeOfOptionalHeader;		// The size of the optional header, in bytes. This value should be 0 for object files
  WORD  Characteristics;			// The characteristics of the image.
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;								// The relative virtual address of the table
  DWORD Size;										// The size of the table, in bytes
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;						// The state of the image file. (0x10b - 32exe, 0x20b - 64exe, 0x107 - ROM Image)
  BYTE                 MajorLinkerVersion;			// The major version number of the linker
  BYTE                 MinorLinkerVersion;			// The minor version number of the linker
  DWORD                SizeOfCode;					// The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections
  DWORD                SizeOfInitializedData;		// The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections
  DWORD                SizeOfUninitializedData;		// The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections
  DWORD                AddressOfEntryPoint;			// A pointer to the entry point function, relative to the image base address. For executable files, this is the starting address
  DWORD                BaseOfCode;					// A pointer to the beginning of the code section, relative to the image base
  DWORD                BaseOfData;					// A pointer to the beginning of the data section, relative to the image base
  DWORD                ImageBase;					// The preferred address of the first byte of the image when it is loaded in memory. This value is a multiple of 64K bytes
  DWORD                SectionAlignment;			// The alignment of sections loaded in memory, in bytes. This value must be greater than or equal to the FileAlignment member.
  DWORD                FileAlignment;				// The alignment of the raw data of sections in the image file, in bytes. The value should be a power of 2 between 512 and 64K (inclusive). The default is 512
  WORD                 MajorOperatingSystemVersion;	// The major version number of the required operating system
  WORD                 MinorOperatingSystemVersion; // The minor version number of the required operating system
  WORD                 MajorImageVersion;			// The major version number of the image
  WORD                 MinorImageVersion;			// The minor version number of the image
  WORD                 MajorSubsystemVersion;		// The major version number of the subsystem
  WORD                 MinorSubsystemVersion;		// The minor version number of the subsystem
  DWORD                Win32VersionValue;			// This member is reserved and must be 0
  DWORD                SizeOfImage;					// The size of the image, in bytes, including all headers. Must be a multiple of SectionAlignment
  DWORD                SizeOfHeaders;				// Size of all headers
  DWORD                CheckSum;					// The image file checksum
  WORD                 Subsystem;					// The subsystem required to run this image
  WORD                 DllCharacteristics;			// The DLL characteristics of the image
  DWORD                SizeOfStackReserve;			// The number of bytes to reserve for the stack
  DWORD                SizeOfStackCommit;			// The number of bytes to commit for the stack
  DWORD                SizeOfHeapReserve;			// The number of bytes to reserve for the local heap
  DWORD                SizeOfHeapCommit;			// The number of bytes to commit for the heap
  DWORD                LoaderFlags;					// This member is obsolete
  DWORD                NumberOfRvaAndSizes;			// The number of directory entries in the remainder of the optional header
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];	// A pointer to the first IMAGE_DATA_DIRECTORY structure in the data directory
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;		// A 4-byte signature identifying the file as a PE image. The bytes are "PE\0\0".
  IMAGE_FILE_HEADER       FileHeader;		// An IMAGE_FILE_HEADER structure that specifies the file header.
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;	// An IMAGE_OPTIONAL_HEADER structure that specifies the optional file header.
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// IMAGE SECTION HEADERS

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];			// An 8-byte, null-padded UTF-8 string.
    union {
            DWORD   PhysicalAddress;				// The file address
            DWORD   VirtualSize;					// The total size of the section when loaded into memory, in bytes
    } Misc;
    DWORD   VirtualAddress;							// The address of the first byte of the section when loaded into memory, relative to the image base
    DWORD   SizeOfRawData;							// The size of the initialized data on disk, in bytes
    DWORD   PointerToRawData;						// A file pointer to the first page within the COFF file
    DWORD   PointerToRelocations;					// A file pointer to the beginning of the relocation entries for the section
    DWORD   PointerToLinenumbers;					// A file pointer to the beginning of the line-number entries for the section
    WORD    NumberOfRelocations;					// The number of relocation entries for the section
    WORD    NumberOfLinenumbers;					// The number of line-number entries for the section
    DWORD   Characteristics;						// The characteristics of the image
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

// IMPORT TABLE DESCRIPTOR - REPRESENTS ONE DLL FILE

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;

#define IMAGE_SIZEOF_IMPORT_DESCRIPTOR		20

// IMAGE THUNK DATA - REPRESENTS ONE FUNCTION
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;							// An index into the export name pointer table
    BYTE    Name[1];						// An ASCII string that contains the name to import
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

#define ORDINAL_FLAG_32						0x80000000

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE 
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;


// EXPORT DIRECTORY

// Export Format
//

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;		// Reserved, must be 0. 
    DWORD   TimeDateStamp;			// The time and date that the export data was created
    WORD    MajorVersion;			// The major version number
    WORD    MinorVersion;			// The minor version number
    DWORD   Name;					// The address of the ASCII string that contains the name of the DLL
    DWORD   Base;					// The starting ordinal number for exports in this image
    DWORD   NumberOfFunctions;		// The number of entries in the export address table.
    DWORD   NumberOfNames;			// The number of entries in the name pointer table. This is also the number of entries in the ordinal table
    DWORD   AddressOfFunctions;     // The address of the export address table, relative to the image base
    DWORD   AddressOfNames;         // The address of the export name pointer table, relative to the image base. The table size is given by the Number of Name Pointers field
    DWORD   AddressOfNameOrdinals;  // The address of the ordinal table, relative to the image base
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

