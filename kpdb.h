#pragma once
#include "ntutils.h" // For PVOID, DWORD, USHORT, ULONG, LPCSTR, etc. (Ensure it defines these or include appropriate headers like ntifs.h)
#include <ntstatus.h> // For NTSTATUS if not in ntutils.h

#ifndef CHAR
typedef char CHAR;
#endif
#ifndef PCHAR
typedef char* PCHAR;
#endif


// Forward declaration for KpdbPDB_CONTEXT
typedef struct KpdbPDB_CONTEXT KpdbPDB_CONTEXT;

// --- PDB Main Structures (from existing code) ---
#define MAX_SYMBOL_DATA 32 // Existing define

typedef struct {
    USHORT reclen;
    USHORT rectyp;
    ULONG pubsymflags;
    ULONG off;
    USHORT seg;
    CHAR name[1];
} PUBSYM32;

typedef struct {
    LPCSTR SymbolName;
    //DWORD SymbolNameHash; // If you plan to use hashing
    ULONG SectionNumber;
    ULONG SectionOffset;
    ULONG_PTR SymbolRVA; // Changed to ULONG_PTR for RVA
} SYMBOL_DATA;

typedef struct {
    CHAR FileMagic[32]; // "Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
    ULONG BlockSize;
    ULONG FreeBlockMapBlock;
    ULONG NumBlocks;
    ULONG NumDirectoryBytes;
    ULONG Unknown;
    ULONG BlockMapAddr; // Block number of an array of ULONGs holding the block numbers for the directory
} SuperBlock;

typedef struct {
    PVOID StreamPointer;
    SIZE_T StreamSize;
} StreamData;

typedef struct { // Partial DBI Header, only what's needed for SymRecordStream
    LONG VerSignature;
    ULONG VerHeader;
    ULONG Age;
    USHORT GsSymStream; // Global symbol stream index.
    USHORT VersBuild;   // pdb.dll build version. eg. 1900 for VS2015
    USHORT PsSymStream; // Public symbol stream index.
    USHORT VersMajor;   // pdb.dll version major
    USHORT VersMinor;   // pdb.dll version minor
    USHORT SymRecordStream; // Index of the symbol record stream. THIS IS WHAT WE WANT
    // ... other fields
} DBIHeader;

// --- PDB Type Information (TPI) Stream Structures ---

// PDB Type Information (TPI/IPI) Stream Header
typedef struct _TPI_HEADER {
    ULONG Version;          // TPI_VERSION_* (e.g. V40, V41, V50, V70, V80)
    ULONG HeaderSize;       // Size of this header structure
    ULONG TypeIndexBegin;   // First type index in this stream (usually 0x1000 for 32-bit TIs)
    ULONG TypeIndexEnd;     // One past the last type index in this stream
    ULONG TypeRecordBytes;  // Total bytes of TPI records that follow this header

    // Hash stream info (can often be ignored for basic parsing)
    USHORT HashStreamIndex;
    USHORT HashAuxStreamIndex; // Unused?
    ULONG HashKeySize;
    ULONG NumHashBuckets;

    // Offsets for hash values, type records, and hash adjusters from start of TPI_HASH_RECORD
    // These are relative to some base within a hash stream or section of TPI stream
    LONG OffHashVals;       // Offset of Type Hash Values buffer
    LONG OffTiOff;          // Offset of Type Index Offsets buffer (CV_पतオフारंभ) from start of TypeRecordBytes data
    LONG OffHashAdj;        // Offset of Hash Record Adjustment Table
} TPI_HEADER, * PTPI_HEADER;

// Leaf type constants (subset relevant for struct/member parsing)
// Refer to CVINFO.H from DIA SDK for a complete list
typedef enum CV_लीफ_e {
    // ... (A more complete list can be added if needed)
    LF_FIELDLIST = 0x1203,

    LF_STRUCTURE = 0x1505, // Used for C structures (struct keyword)
    LF_CLASS = 0x1504,     // Used for C++ classes (class keyword)
    LF_UNION = 0x1506,     // Used for C/C++ unions (union keyword)
    LF_ENUM = 0x1507,      // Used for enums

    LF_MEMBER = 0x150d,    // Non-static data member of a class/struct/union
    LF_STMEMBER = 0x150e,  // Static data member

    // Numeric leafs
    LF_NUMERIC = 0x8000, // Marker for variable-length numeric fields
    LF_CHAR_NUM = 0x8000, // Used if numeric data is char (distinguish from LF_CHAR type)
    LF_SHORT_NUM = 0x8001,
    LF_USHORT_NUM = 0x8002,
    LF_LONG_NUM = 0x8003,
    LF_ULONG_NUM = 0x8004,
    // ... other numeric types (float, double, etc.)
} CV_लीफ_e;

// Basic type index - PDBs use this to refer to other types.
// Modern PDBs mostly use 32-bit type indices.
typedef ULONG CV_typ_t;

// Structure for parsed type field/member information
typedef struct _TYPE_MEMBER_INFO {
    CHAR Name[256];     // Member name
    ULONG Offset;       // Offset within the parent aggregate
    CV_typ_t TypeIndex; // Type index of this member
    USHORT Attributes;  // CV_fldattr_t (access specifiers, properties)
} TYPE_MEMBER_INFO, * PTYPE_MEMBER_INFO;

// Structure for parsed struct/class/union information
typedef struct _TYPE_AGGREGATE_INFO {
    CHAR Name[256];          // Aggregate type name
    CV_typ_t TypeIndex;      // Its own type index in the PDB
    USHORT MemberCount;      // Number of members successfully parsed
    PTYPE_MEMBER_INFO Members;// Array of members
    ULONG Size;              // Size of the aggregate type in bytes
    CV_लीफ_e Kind;          // LF_STRUCTURE, LF_CLASS, or LF_UNION
    // Add other fields if needed: CV_prop_t properties, LF_FIELDLIST index, etc.
} TYPE_AGGREGATE_INFO, * PTYPE_AGGREGATE_INFO;

#define MAX_PARSED_TYPES 16   // Max aggregate types to store (adjust as needed)
#define MAX_MEMBERS_PER_TYPE 64 // Max members per aggregate type (adjust as needed)


// Context structure to hold PDB parsing state, including TPI info
struct KpdbPDB_CONTEXT {
    PVOID PdbFileBase;        // Base address of the loaded PDB file content
    SuperBlock* Superblock;   // Pointer to the PDB superblock
    StreamData* AllStreams;   // Array of all streams in the PDB
    DWORD NumStreams;         // Count of streams in AllStreams

    // TPI Stream specific data
    PCHAR TpiStream;          // Pointer to the reassembled TPI stream data
    DWORD TpiStreamSize;      // Size of the TpiStream data
    TPI_HEADER TpiHeader;     // Parsed TPI header
    // Array of PCHAR, where each element points to the start (reclen field)
    // of a type record within TpiStream. Indexed by (TypeIndex - TpiHeader.TypeIndexBegin).
    PCHAR* TypeRecordIndex;   
    DWORD TypeRecordCount;    // TpiHeader.TypeIndexEnd - TpiHeader.TypeIndexBegin

    // Storage for user-requested parsed types
    TYPE_AGGREGATE_INFO ParsedAggregates[MAX_PARSED_TYPES];
    DWORD ParsedAggregateCount;
};


// --- Function Prototypes ---

// Existing
BOOL KpdbIsPDBMagicValid(SuperBlock* super);
PVOID KpdbGetPDBStreamDirectory(PVOID base);
StreamData* KpdbGetPDBStreams(PVOID base, PDWORD streams_count);
BOOL KpdbGetPDBSymbolOffset(PVOID pdbfile, PSYMBOL_DATA SymbolDataList);
void KpdbConvertSecOffsetToRVA(ULONG_PTR ModuleBase, PSYMBOL_DATA SymbolDataList);

// New TPI parsing functions
BOOL KpdbReadNumeric(PCHAR* ppData, PCHAR pEndData, PULONG pValue);
void KpdbSkipPadding(PCHAR* ppData, PCHAR pEndRecord);

BOOL KpdbInitializeContext(KpdbPDB_CONTEXT* Context, PVOID PdbFileBase);
void KpdbFreeContext(KpdbPDB_CONTEXT* Context);

BOOL KpdbGetTypeRecord(KpdbPDB_CONTEXT* Context, CV_typ_t TypeIndex, 
                       PUSHORT pLeaf, PCHAR* ppDataStart, PUSHORT pcbData);

BOOL KpdbGetFieldListMembers(KpdbPDB_CONTEXT* Context, CV_typ_t FieldListTypeIndex, 
                             TYPE_AGGREGATE_INFO* pAggregateInfo);

BOOL KpdbParseAggregateTypeByName(KpdbPDB_CONTEXT* Context, LPCSTR TypeName, 
                                  PTYPE_AGGREGATE_INFO* ppFoundTypeInfo); // Returns pointer into Context->ParsedAggregates


// From DriverEntry.h (or kpdb_demo.h, keep them separate)
void KpdbDemoRoutine();
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

#ifdef __cplusplus
extern "C" {
#endif
    // For strcmp, strlen etc. if not included by ntifs.h or other system headers
    #include <string.h> 
#ifdef __cplusplus
}
#endif
