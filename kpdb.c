#include "kpdb.h"
#include <ntimage.h> // For PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER

// For DbgPrintEx - ensure this is available.
// For ExAllocatePool, ExFreePool
// Ensure ntifs.h or equivalent is included via ntutils.h or kpdb.h for these definitions if not globally.


const char kMagic[] = {
	0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F,
	0x43, 0x2B, 0x2B, 0x20, 0x4D, 0x53, 0x46, 0x20, 0x37, 0x2E, 0x30, 0x30,
	0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00
};

BOOL KpdbIsPDBMagicValid(SuperBlock* super) {
	return 0 == memcmp(super->FileMagic, kMagic, sizeof(kMagic));
}

PVOID KpdbGetPDBStreamDirectory(PVOID base) {
	SuperBlock* super = (SuperBlock*)base;
	DWORD size = super->NumDirectoryBytes;
	DWORD block_size = super->BlockSize;
	DWORD block_count = (size + block_size - 1) / block_size;
	PDWORD block_id_array = (PDWORD)((BYTE*)base + block_size * super->BlockMapAddr);
	PVOID stream_dir = NULL;

    if (block_size == 0) { // Avoid division by zero
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreamDirectory: Invalid block_size (0).\n");
        return NULL;
    }
    if (block_count > (MAXULONG / block_size) ) { // Check for overflow before allocation
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreamDirectory: block_count * block_size would overflow.\n");
        return NULL;
    }


	stream_dir = ExAllocatePool(PagedPool, block_count * block_size);
    if (!stream_dir) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreamDirectory: Failed to allocate memory for stream directory.\n");
        return NULL;
    }

	PCHAR end_of_stream = (PCHAR)stream_dir;
	for (DWORD i = 0; i < block_count; ++i) {
        if (block_id_array[i] >= super->NumBlocks) { // bounds check
            DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreamDirectory: Invalid block_id %u.\n", block_id_array[i]);
            ExFreePool(stream_dir);
            return NULL;
        }
		PCHAR block = (PCHAR)base + block_size * block_id_array[i];
		memcpy(end_of_stream, block, block_size);
		end_of_stream += block_size;
	}

	return stream_dir;
}

StreamData* KpdbGetPDBStreams(PVOID base, PDWORD streams_count) {
	SuperBlock* super = (SuperBlock*)base;
	if (!KpdbIsPDBMagicValid(super)) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreams: Invalid PDB magic.\n");
        return NULL;
    }
	DWORD block_size = super->BlockSize;

    if (block_size == 0) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreams: Invalid block_size (0).\n");
        return NULL;
    }

	PVOID stream_dir = KpdbGetPDBStreamDirectory(base);
    if (!stream_dir) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreams: Failed to get stream directory.\n");
        return NULL;
    }

	PDWORD ui32_iter = (PDWORD)stream_dir;
	DWORD stream_num = *ui32_iter++;
    if (stream_num == 0 || stream_num > 10000) { // Sanity check for stream_num
        DbgPrintEx(0,0, "[KPDB] KpdbGetPDBStreams: Invalid number of PDB streams: %u\n", stream_num);
        ExFreePool(stream_dir);
        return NULL;
    }

	PDWORD stream_array = ui32_iter; // These are stream sizes
	ui32_iter += stream_num; // ui32_iter now points to the start of block id lists for each stream

    if ((PCHAR)ui32_iter > (PCHAR)stream_dir + super->NumDirectoryBytes) {
         DbgPrintEx(0,0, "[KPDB] KpdbGetPDBStreams: Stream directory parsing overrun.\n");
         ExFreePool(stream_dir);
         return NULL;
    }


	StreamData* streams = (StreamData*)ExAllocatePool(PagedPool, stream_num * sizeof(StreamData));
    if (!streams) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreams: Failed to allocate memory for StreamData array.\n");
        ExFreePool(stream_dir);
        return NULL;
    }
	*streams_count = 0;

	for (DWORD i = 0; i < stream_num; ++i) {
		PCHAR current_stream = NULL;
		DWORD current_stream_size = stream_array[i]; // Size of this specific stream
        if (current_stream_size == 0xFFFFFFFF || current_stream_size == 0) { // Stream is empty or non-existent
            streams[*streams_count].StreamPointer = NULL;
            streams[*streams_count].StreamSize = 0;
            (*streams_count)++;
            continue;
        }

		DWORD current_stream_block_count = (current_stream_size + block_size - 1) / block_size;
        if (current_stream_block_count > (MAXULONG / block_size)) {
            DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreams: current_stream_block_count * block_size overflow for stream %u\n", i);
            // Free previously allocated streams and return
            for (DWORD k = 0; k < *streams_count; ++k) ExFreePool(streams[k].StreamPointer);
            ExFreePool(streams);
            ExFreePool(stream_dir);
            return NULL;
        }

		current_stream = (PCHAR)ExAllocatePool(PagedPool, current_stream_block_count * block_size);
        if (!current_stream) {
            DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreams: Failed to allocate memory for stream %u content.\n", i);
            // Free previously allocated streams and return
            for (DWORD k = 0; k < *streams_count; ++k) ExFreePool(streams[k].StreamPointer);
            ExFreePool(streams);
            ExFreePool(stream_dir);
            return NULL;
        }

		PCHAR end_of_this_stream = current_stream;
		for (DWORD j = 0; j < current_stream_block_count; ++j) {
			DWORD block_id = *ui32_iter++;
            if (block_id >= super->NumBlocks) { // bounds check
                DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBStreams: Invalid block_id %u for stream %u.\n", block_id, i);
                ExFreePool(current_stream);
                 for (DWORD k = 0; k < *streams_count; ++k) ExFreePool(streams[k].StreamPointer);
                ExFreePool(streams);
                ExFreePool(stream_dir);
                return NULL;
            }
            if((PCHAR)ui32_iter > (PCHAR)stream_dir + super->NumDirectoryBytes){
                 DbgPrintEx(0,0, "[KPDB] KpdbGetPDBStreams: Stream directory block list parsing overrun for stream %u.\n", i);
                 ExFreePool(current_stream);
                 for (DWORD k = 0; k < *streams_count; ++k) ExFreePool(streams[k].StreamPointer);
                ExFreePool(streams);
                ExFreePool(stream_dir);
                return NULL;
            }

			PCHAR block_content = (PCHAR)base + (block_size * block_id);
			memcpy(end_of_this_stream, block_content, block_size);
			end_of_this_stream += block_size;
		}

		streams[*streams_count].StreamPointer = current_stream;
		streams[*streams_count].StreamSize = current_stream_size; // Store actual size, not allocated block size
		(*streams_count)++;
	}

	ExFreePool(stream_dir);
	return streams;
}

BOOL KpdbGetPDBSymbolOffset(PVOID pdbfile, PSYMBOL_DATA SymbolDataList) {
	PCHAR symbols = NULL;
	StreamData* streams = NULL;
	DWORD streams_count = 0;
	SIZE_T symbolsstreamsize = 0;
	// DWORD SymbolsCollected = 0; // Not used

	streams = KpdbGetPDBStreams(pdbfile, &streams_count);
	if (!streams) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBSymbolOffset: KpdbGetPDBStreams failed.\n");
        return FALSE;
    }

    // Check if enough streams are present
    if (streams_count < 4) { // Need at least PDB Stream (0), TPI (2), DBI (3)
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBSymbolOffset: Not enough streams found (%u).\n", streams_count);
        // Free allocated streams (even if some are NULL)
        for (DWORD i = 0; i < streams_count; i++) {
		    if(streams[i].StreamPointer) ExFreePool(streams[i].StreamPointer);
	    }
	    ExFreePool(streams);
        return FALSE;
    }
    if (!streams[3].StreamPointer) { // DBI stream specifically
         DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBSymbolOffset: DBI Stream (index 3) is missing.\n");
        for (DWORD i = 0; i < streams_count; i++) {
		    if(streams[i].StreamPointer) ExFreePool(streams[i].StreamPointer);
	    }
	    ExFreePool(streams);
        return FALSE;
    }

    DBIHeader* dbiHdr = (DBIHeader*)streams[3].StreamPointer;
    if (dbiHdr->SymRecordStream >= streams_count || !streams[dbiHdr->SymRecordStream].StreamPointer) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBSymbolOffset: Invalid SymRecordStream index (%u) or stream missing.\n", dbiHdr->SymRecordStream);
        for (DWORD i = 0; i < streams_count; i++) {
		    if(streams[i].StreamPointer) ExFreePool(streams[i].StreamPointer);
	    }
	    ExFreePool(streams);
        return FALSE;
    }

	// types = streams[2].StreamPointer; // Not used in this function but this is TPI
	symbols = streams[dbiHdr->SymRecordStream].StreamPointer;
	symbolsstreamsize = streams[dbiHdr->SymRecordStream].StreamSize;

	{
		PCHAR it = symbols;
		const PCHAR end = (PCHAR)((ULONG_PTR)it + symbolsstreamsize);
		while (it < end) // Use < to avoid issues if end points just past valid memory
		{
            if ((ULONG_PTR)it + sizeof(PUBSYM32) > (ULONG_PTR)end) break; // Bounds check

			const PUBSYM32* curr = (PUBSYM32*)it;
            if (curr->reclen == 0) { // Avoid infinite loop on malformed PDB
                DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBSymbolOffset: Encountered S_PUB32 record with reclen 0. Aborting symbol scan.\n");
                break;
            }
            // Basic check on reclen to prevent large erroneous skips
            if (curr->reclen > symbolsstreamsize) { 
                DbgPrintEx(0, 0, "[KPDB] KpdbGetPDBSymbolOffset: Encountered S_PUB32 record with suspicious reclen %u. Aborting.\n", curr->reclen);
                break;
            }


			if (curr->rectyp == 0x110E /*S_PUB32*/) // MS Symbol Server PDBs use S_PUB32_NEW (0x110E), old was S_PUB32 (0x0109)
			{                                       // Let's keep it general by not hardcoding S_PUB32
				DWORD iteration = 0;
				while (SymbolDataList[iteration].SymbolName) {
                    // Check curr->name is not past end of symbol stream
                    // This strlen could be unsafe if curr->name is not null-terminated within reclen
                    // PUBSYM32 name is null terminated and part of the record of length 'reclen'
                    PCHAR name_ptr = (PCHAR)curr->name;
                    ULONG_PTR name_end_ptr = (ULONG_PTR)it + 2 + curr->reclen; // +2 for reclen itself
                    BOOLEAN name_valid = FALSE;
                    for(PCHAR p = name_ptr; (ULONG_PTR)p < name_end_ptr; ++p) {
                        if (*p == '\0') {
                            name_valid = TRUE;
                            break;
                        }
                    }
                    if (!name_valid) {
                        DbgPrintEx(0,0, "[KPDB] KpdbGetPDBSymbolOffset: Symbol name not null-terminated within record length.\n");
                        // Potentially skip this record, or break. For now, continue to next record carefully.
                        goto next_symbol_record;
                    }

					if (strcmp(curr->name, SymbolDataList[iteration].SymbolName) == 0) {
						DbgPrintEx(0, 0, "[KPDB] SYMBOL S_PUB32: [%04X:%08X], Flags : %08X, %s\n", curr->seg, curr->off, curr->pubsymflags, curr->name);
						SymbolDataList[iteration].SectionNumber = curr->seg;
						SymbolDataList[iteration].SectionOffset = curr->off;
						// SymbolsCollected++; // Not strictly needed for operation
						break; // Found this symbol, move to next in SymbolDataList
					}
					iteration++;
				}
			}
        next_symbol_record:
            if ((ULONG_PTR)it + curr->reclen + sizeof(USHORT) > (ULONG_PTR)end) break; // reclen is length of data *after* rectyp
			it += curr->reclen + sizeof(USHORT); // Add size of reclen field itself
		}
	}

	// Free all of the streams and free the stream data array
	for (DWORD i = 0; i < streams_count; i++) {
		if(streams[i].StreamPointer) ExFreePool(streams[i].StreamPointer);
	}
	ExFreePool(streams);

	return TRUE;
}

void KpdbConvertSecOffsetToRVA(ULONG_PTR ModuleBase, PSYMBOL_DATA SymbolDataList) {
    if (!ModuleBase) {
        DbgPrintEx(0,0, "[KPDB] KpdbConvertSecOffsetToRVA: ModuleBase is NULL.\n");
        return;
    }
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        DbgPrintEx(0,0, "[KPDB] KpdbConvertSecOffsetToRVA: Invalid DOS signature.\n");
        return;
    }
    // Ensure e_lfanew is within reasonable bounds if ModuleBase points to mapped PE file in memory
    // This check is basic; a full PE validation is complex.
    // Assuming ModuleBase is just a base address and e_lfanew points within the mapped module.

	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)(ModuleBase + DosHeader->e_lfanew);
    if (NTHeader->Signature != IMAGE_NT_SIGNATURE) {
        DbgPrintEx(0,0, "[KPDB] KpdbConvertSecOffsetToRVA: Invalid NT signature.\n");
        return;
    }

	PIMAGE_SECTION_HEADER SectionHeaderBaseAddr = IMAGE_FIRST_SECTION(NTHeader);

	DWORD Iterator = 0;
	while (SymbolDataList[Iterator].SymbolName && SymbolDataList[Iterator].SectionOffset) { // Check SymbolName also to stop on empty entry
        if (SymbolDataList[Iterator].SectionNumber > 0 && 
            SymbolDataList[Iterator].SectionNumber <= NTHeader->FileHeader.NumberOfSections) {
            // SectionNumber is 1-based
		    SymbolDataList[Iterator].SymbolRVA = SymbolDataList[Iterator].SectionOffset + 
                SectionHeaderBaseAddr[SymbolDataList[Iterator].SectionNumber - 1].VirtualAddress;
        } else if (SymbolDataList[Iterator].SectionNumber != 0) { // Section 0 is IMAGE_SYM_ABSOLUTE, RVA is just offset.
             DbgPrintEx(0,0, "[KPDB] KpdbConvertSecOffsetToRVA: Invalid section number %u for symbol %s.\n",
                SymbolDataList[Iterator].SectionNumber, SymbolDataList[Iterator].SymbolName);
            SymbolDataList[Iterator].SymbolRVA = 0; // Or some error indicator
        } else { // For IMAGE_SYM_ABSOLUTE, RVA is just offset (typically for constants)
            SymbolDataList[Iterator].SymbolRVA = SymbolDataList[Iterator].SectionOffset;
        }
		Iterator++;
	}
}


// --- New TPI Parsing Functions ---

// Reads a PDB numeric value (typically ULF_NUMERIC or similar)
// Advances *ppData past the consumed bytes.
// pEndData points to one byte beyond the end of the buffer being parsed (e.g. record end)
BOOL KpdbReadNumeric(PCHAR* ppData, PCHAR pEndData, PULONG pValue) {
    PCHAR p = *ppData;
    USHORT leaf_val;

    if (p + sizeof(USHORT) > pEndData) return FALSE; // Not enough data for leaf_val
    leaf_val = *(USHORT*)p;

    if (leaf_val < LF_NUMERIC) { // 0x8000
        *pValue = leaf_val;
        *ppData = p + sizeof(USHORT);
        return TRUE;
    }

    p += sizeof(USHORT); // Skip the leaf_val itself

    switch (leaf_val) {
        case LF_CHAR_NUM: // 0x8000
            if (p + sizeof(CHAR) > pEndData) return FALSE;
            *pValue = (ULONG)(*(CHAR*)p);
            *ppData = p + sizeof(CHAR);
            return TRUE;
        case LF_SHORT_NUM: // 0x8001
            if (p + sizeof(SHORT) > pEndData) return FALSE;
            *pValue = (ULONG)(*(SHORT*)p);
            *ppData = p + sizeof(SHORT);
            return TRUE;
        case LF_USHORT_NUM: // 0x8002
            if (p + sizeof(USHORT) > pEndData) return FALSE;
            *pValue = (ULONG)(*(USHORT*)p);
            *ppData = p + sizeof(USHORT);
            return TRUE;
        case LF_LONG_NUM: // 0x8003
            if (p + sizeof(LONG) > pEndData) return FALSE;
            *pValue = (ULONG)(*(LONG*)p); // Potential truncation if LONG > ULONG, but usually fine
            *ppData = p + sizeof(LONG);
            return TRUE;
        case LF_ULONG_NUM: // 0x8004
            if (p + sizeof(ULONG) > pEndData) return FALSE;
            *pValue = *(ULONG*)p;
            *ppData = p + sizeof(ULONG);
            return TRUE;
        default:
            DbgPrintEx(0, 0, "[KPDB] KpdbReadNumeric: Unsupported numeric leaf 0x%X\n", leaf_val);
            return FALSE;
    }
}

// Aligns the pointer *ppData to the next 4-byte boundary, if not already aligned.
// pEndRecord is used to ensure we don't read past the end of current record while advancing.
void KpdbSkipPadding(PCHAR* ppData, PCHAR pEndRecord) {
    ULONG_PTR ptr = (ULONG_PTR)(*ppData);
    ULONG_PTR aligned_ptr = (ptr + 3) & ~3;
    if (aligned_ptr > (ULONG_PTR)pEndRecord) { // Check if alignment causes overrun
        *ppData = pEndRecord; // Move to end if padding would cross boundary
    } else {
        *ppData = (PCHAR)aligned_ptr;
    }
}


BOOL KpdbInitializeContext(KpdbPDB_CONTEXT* Context, PVOID PdbFileBase) {
    PCHAR pTypeRecordWalker;
    DWORD i;

    if (!Context || !PdbFileBase) return FALSE;
    memset(Context, 0, sizeof(KpdbPDB_CONTEXT)); // Zero out context

    Context->PdbFileBase = PdbFileBase;
    Context->Superblock = (SuperBlock*)PdbFileBase;

    Context->AllStreams = KpdbGetPDBStreams(PdbFileBase, &Context->NumStreams);
    if (!Context->AllStreams) {
        DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: KpdbGetPDBStreams failed.\n");
        return FALSE;
    }

    // TPI Stream is typically stream 2 (0-indexed: streams[2])
    if (Context->NumStreams <= 2 || !Context->AllStreams[2].StreamPointer || Context->AllStreams[2].StreamSize < sizeof(TPI_HEADER)) {
        DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: TPI Stream (index 2) missing or too small.\n");
        KpdbFreeContext(Context); // Frees AllStreams
        return FALSE;
    }

    Context->TpiStream = Context->AllStreams[2].StreamPointer;
    Context->TpiStreamSize = (DWORD)Context->AllStreams[2].StreamSize; // Cast from SIZE_T

    // Parse TPI Header
    memcpy(&Context->TpiHeader, Context->TpiStream, sizeof(TPI_HEADER));

    // Basic validation of TPI header (more checks can be added)
    if (Context->TpiHeader.HeaderSize > Context->TpiStreamSize ||
        Context->TpiHeader.TypeIndexBegin >= Context->TpiHeader.TypeIndexEnd) {
        DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: Invalid TPI Header values.\n");
        KpdbFreeContext(Context);
        return FALSE;
    }
    if (Context->TpiHeader.TypeIndexBegin < 0x1000 && Context->TpiHeader.Version >= 0x19970605 /* V50 */) {
         DbgPrintEx(0,0, "[KPDB] KpdbInitializeContext: TPI TypeIndexBegin is %X, expected >= 0x1000 for TPI Version %X \n",
            Context->TpiHeader.TypeIndexBegin, Context->TpiHeader.Version);
        // This is more of a warning; old PDBs might use smaller base indices. Proceed with caution.
    }


    Context->TypeRecordCount = Context->TpiHeader.TypeIndexEnd - Context->TpiHeader.TypeIndexBegin;
    if (Context->TypeRecordCount == 0 || Context->TypeRecordCount > 0x1000000) { // Sanity check type count
         DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: Invalid TypeRecordCount: %u\n", Context->TypeRecordCount);
         KpdbFreeContext(Context);
         return FALSE;
    }

    Context->TypeRecordIndex = ExAllocatePool(PagedPool, Context->TypeRecordCount * sizeof(PCHAR));
    if (!Context->TypeRecordIndex) {
        DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: Failed to allocate TypeRecordIndex.\n");
        KpdbFreeContext(Context);
        return FALSE;
    }
    memset(Context->TypeRecordIndex, 0, Context->TypeRecordCount * sizeof(PCHAR));


    // Index all type records by storing pointers to their start (reclen field)
    pTypeRecordWalker = Context->TpiStream + Context->TpiHeader.HeaderSize;
    PCHAR pEndOfTpiRecords = Context->TpiStream + Context->TpiHeader.HeaderSize + Context->TpiHeader.TypeRecordBytes;
    if (pEndOfTpiRecords > Context->TpiStream + Context->TpiStreamSize) {
        DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: TPI TypeRecordBytes extends beyond stream size.\n");
        KpdbFreeContext(Context);
        return FALSE;
    }

    for (i = 0; i < Context->TypeRecordCount; ++i) {
        USHORT recLen;
        if (pTypeRecordWalker + sizeof(USHORT) > pEndOfTpiRecords) { // Check for reading reclen
            DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: Ran out of TPI data while indexing records (at index %u).\n", i);
            break; // Partial index, might be usable or lead to errors later
        }
        
        Context->TypeRecordIndex[i] = pTypeRecordWalker;
        recLen = *(USHORT*)pTypeRecordWalker; // Length of data *after* leaf type field

        if (recLen == 0) { // Malformed record or padding?
             DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: Encountered type record with reclen 0 at index %u. Stopping scan.\n", i);
             break;
        }

        // Next record = current + sizeof(reclen) + sizeof(leaf) + reclen_data_itself
        // But PDB records' reclen often *doesn't* include the leaf itself in its size, it is data *after* leaf
        // Total record on disk: sizeof(USHORT) reclen + sizeof(USHORT) leaf + data(reclen bytes).
        // Actually, reclen = length of current type record, *excluding* the reclen field itself.
        // So advance by reclen + sizeof(USHORT for reclen field)
        pTypeRecordWalker += recLen + sizeof(USHORT); 

        if (pTypeRecordWalker > pEndOfTpiRecords) {
            DbgPrintEx(0, 0, "[KPDB] KpdbInitializeContext: Type record scan overran TypeRecordBytes (at index %u).\n", i);
            break;
        }
    }
    if (i < Context->TypeRecordCount) {
        DbgPrintEx(0,0, "[KPDB] Warning: Indexed only %u of %u TPI records due to parsing issue or end of data.\n", i, Context->TypeRecordCount);
        Context->TypeRecordCount = i; // Adjust to successfully indexed count
    }


    return TRUE;
}

void KpdbFreeContext(KpdbPDB_CONTEXT* Context) {
    if (!Context) return;

    if (Context->AllStreams) {
        for (DWORD i = 0; i < Context->NumStreams; ++i) {
            if (Context->AllStreams[i].StreamPointer) {
                ExFreePool(Context->AllStreams[i].StreamPointer);
            }
        }
        ExFreePool(Context->AllStreams);
        Context->AllStreams = NULL; // Important: Nullify after free
        Context->TpiStream = NULL; // TpiStream was a pointer into AllStreams[2]
    }

    if (Context->TypeRecordIndex) {
        ExFreePool(Context->TypeRecordIndex);
        Context->TypeRecordIndex = NULL;
    }

    // Free members arrays within ParsedAggregates
    for (DWORD i = 0; i < Context->ParsedAggregateCount; ++i) {
        if (Context->ParsedAggregates[i].Members) {
            ExFreePool(Context->ParsedAggregates[i].Members);
            Context->ParsedAggregates[i].Members = NULL;
        }
    }
    Context->ParsedAggregateCount = 0;
}

// Retrieves information about a specific type record given its TypeIndex.
// ppDataStart will point to the data portion (after leaf field).
// pcbData will receive the length of that data portion (the original reclen field).
BOOL KpdbGetTypeRecord(KpdbPDB_CONTEXT* Context, CV_typ_t TypeIndex,
                       PUSHORT pLeaf, PCHAR* ppDataStart, PUSHORT pcbData) {
    PCHAR pRecordBase;
    DWORD actualIndex;

    if (!Context || !Context->TypeRecordIndex || !pLeaf || !ppDataStart || !pcbData) return FALSE;
    if (TypeIndex < Context->TpiHeader.TypeIndexBegin || TypeIndex >= Context->TpiHeader.TypeIndexEnd) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetTypeRecord: TypeIndex 0x%X out of bounds (0x%X - 0x%X).\n",
            TypeIndex, Context->TpiHeader.TypeIndexBegin, Context->TpiHeader.TypeIndexEnd);
        return FALSE;
    }

    actualIndex = TypeIndex - Context->TpiHeader.TypeIndexBegin;
    if (actualIndex >= Context->TypeRecordCount) { // If count was adjusted during init
        DbgPrintEx(0, 0, "[KPDB] KpdbGetTypeRecord: actualIndex %u out of effective TypeRecordCount %u.\n",
            actualIndex, Context->TypeRecordCount);
        return FALSE;
    }

    pRecordBase = Context->TypeRecordIndex[actualIndex];
    if (!pRecordBase) {
         DbgPrintEx(0, 0, "[KPDB] KpdbGetTypeRecord: No record found at TypeIndex 0x%X (actual index %u).\n", TypeIndex, actualIndex);
        return FALSE;
    }


    // pRecordBase points to 'reclen' field
    // Boundary check: Ensure we can read reclen and leaf from pRecordBase
    // The TpiStream ends at Context->TpiStream + Context->TpiStreamSize
    PCHAR tpiEnd = Context->TpiStream + Context->TpiStreamSize;
    if (pRecordBase + sizeof(USHORT) * 2 > tpiEnd) { // Check for reading reclen + leaf
        DbgPrintEx(0,0,"[KPDB] KpdbGetTypeRecord: pRecordBase for TI 0x%X is too close to TPI stream end for header.\n", TypeIndex);
        return FALSE;
    }

    *pcbData = *(USHORT*)pRecordBase;         // This is the original 'reclen' field of the record
    *pLeaf = *(USHORT*)(pRecordBase + sizeof(USHORT));
    *ppDataStart = pRecordBase + 2 * sizeof(USHORT); // Data starts after reclen and leaf

    // Boundary check: Ensure the record data itself is within TPI stream bounds
    if (*ppDataStart + *pcbData > tpiEnd) {
        DbgPrintEx(0,0,"[KPDB] KpdbGetTypeRecord: Record data for TI 0x%X (len %u) extends beyond TPI stream end.\n", TypeIndex, *pcbData);
        return FALSE; // Record data itself would be out of bounds
    }

    return TRUE;
}

// Parses LF_FIELDLIST and populates members for an aggregate type
BOOL KpdbGetFieldListMembers(KpdbPDB_CONTEXT* Context, CV_typ_t FieldListTypeIndex,
                             TYPE_AGGREGATE_INFO* pAggregateInfo) {
    USHORT flLeaf, flRecLen;
    PCHAR pFieldListData, pIter, pEndFieldList;
    USHORT membersAllocated = 0;

    if (!KpdbGetTypeRecord(Context, FieldListTypeIndex, &flLeaf, &pFieldListData, &flRecLen)) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: Could not get FieldList record 0x%X.\n", FieldListTypeIndex);
        return FALSE;
    }

    if (flLeaf != LF_FIELDLIST) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: TypeIndex 0x%X is not LF_FIELDLIST (is 0x%X).\n", FieldListTypeIndex, flLeaf);
        return FALSE;
    }

    pIter = pFieldListData;
    pEndFieldList = pFieldListData + flRecLen;
    pAggregateInfo->MemberCount = 0;

    // Pre-allocate based on parent's count field if available, or a default max.
    // For now, use fixed MAX_MEMBERS_PER_TYPE
    // The 'count' in LF_STRUCTURE might not be just LF_MEMBERs, could include methods, nested types, etc.
    // So iterating until LF_FIELDLIST end is more robust.
    pAggregateInfo->Members = ExAllocatePool(PagedPool, MAX_MEMBERS_PER_TYPE * sizeof(TYPE_MEMBER_INFO));
    if (!pAggregateInfo->Members) {
        DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: Failed to allocate memory for members.\n");
        return FALSE;
    }
    membersAllocated = MAX_MEMBERS_PER_TYPE;
    RtlZeroMemory(pAggregateInfo->Members, membersAllocated * sizeof(TYPE_MEMBER_INFO));


    while (pIter < pEndFieldList) {
        USHORT memberLeaf;
        TYPE_MEMBER_INFO* currentMember = NULL; // Initialized to NULL

        if (pIter + sizeof(USHORT) > pEndFieldList) break; // Not enough data for leaf
        memberLeaf = *(USHORT*)pIter;
        pIter += sizeof(USHORT);

        if (memberLeaf == LF_MEMBER || memberLeaf == LF_STMEMBER) {
            if (pAggregateInfo->MemberCount >= membersAllocated) {
                // This shouldn't happen with MAX_MEMBERS_PER_TYPE if it's large enough
                // Or implement dynamic reallocation if strictly needed
                DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: Exceeded max members for %s.\n", pAggregateInfo->Name);
                break;
            }
            currentMember = &pAggregateInfo->Members[pAggregateInfo->MemberCount];

            // Parse LF_MEMBER / LF_STMEMBER:
            // struct LF_MEMBER_S {
            //    unsigned short  attrib;     // member attributes
            //    CV_typ_t        index;      // type index of member
            //    unsigned char   CV_FAR *idoffset; // variant length offset of member
            //    unsigned char   name[];     // length prefixed name
            // };
            if (pIter + sizeof(USHORT) + sizeof(CV_typ_t) > pEndFieldList) break; // Attr + index

            currentMember->Attributes = *(USHORT*)pIter;
            pIter += sizeof(USHORT);

            currentMember->TypeIndex = *(CV_typ_t*)pIter;
            pIter += sizeof(CV_typ_t);

            if (!KpdbReadNumeric(&pIter, pEndFieldList, ¤tMember->Offset)) {
                DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: Failed to read numeric offset for member.\n");
                // This member is corrupt, might need to skip the field list. For now, break.
                break; 
            }

            // Name is null-terminated
            if (pIter >= pEndFieldList || *pIter == '\0' /* Empty name unusual */) {
                 DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: Member name points to end or is empty string.\n");
                 // Set a default name or break
                 strcpy_s(currentMember->Name, sizeof(currentMember->Name), "<UnnamedMember>");
                 if(pIter < pEndFieldList && *pIter == '\0') pIter++; // Consume the null terminator for empty name
            } else {
                size_t nameLen = strlen(pIter);
                if (pIter + nameLen + 1 > pEndFieldList) { // Check for buffer overflow on name + null
                    DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: Member name + NUL exceeds FieldList boundary.\n");
                    break;
                }
                strcpy_s(currentMember->Name, sizeof(currentMember->Name), pIter);
                pIter += nameLen + 1; // Advance past name and its NUL terminator
            }
            
            pAggregateInfo->MemberCount++;
            if (memberLeaf == LF_STMEMBER) {
                 // For static members, offset is RVA, not struct offset. Note this if needed.
                 DbgPrintEx(0,0, "[KPDB] Member %s is static. Offset 0x%X is an RVA.\n", currentMember->Name, currentMember->Offset);
            }

        } else {
            // Skip other LF_xxxx types within LF_FIELDLIST. This is complex.
            // LF_ENUMERATE:  attributes (USHORT), value (numeric), name (string)
            // LF_NESTTYPE:   attributes (USHORT), typeindex (CV_typ_t), name (string)
            // LF_METHOD:     count (USHORT), mList (CV_typ_t), name (string)
            // LF_BCLASS:     attributes (USHORT), type (CV_typ_t), offset (numeric)
            // LF_VFUNCTAB:   pad (USHORT), type (CV_typ_t)
            // Many require careful parsing to know how many bytes to skip.
            // For this exercise, we'll break if we see an unhandled type in fieldlist,
            // as skipping them correctly without full parsing logic is error-prone.
            DbgPrintEx(0, 0, "[KPDB] KpdbGetFieldListMembers: Unhandled leaf 0x%X in FieldList for %s. Stopping member parse.\n",
                memberLeaf, pAggregateInfo->Name);
            break; // Simplification: stop at first non-LF_MEMBER type.
        }

        // Align pIter to next 4-byte boundary before next field list item.
        // This is crucial as each item within LF_FIELDLIST starts aligned.
        KpdbSkipPadding(&pIter, pEndFieldList);
    }
    return TRUE;
}

BOOL KpdbParseAggregateTypeByName(KpdbPDB_CONTEXT* Context, LPCSTR TypeName,
                                  PTYPE_AGGREGATE_INFO* ppFoundTypeInfo) {
    USHORT recLeaf, recLenData;
    PCHAR pRecData;

    if (!Context || !TypeName || !ppFoundTypeInfo) return FALSE;
    *ppFoundTypeInfo = NULL;

    if (Context->ParsedAggregateCount >= MAX_PARSED_TYPES) {
        DbgPrintEx(0, 0, "[KPDB] KpdbParseAggregateTypeByName: Max parsed types limit reached.\n");
        return FALSE;
    }

    for (CV_typ_t ti = Context->TpiHeader.TypeIndexBegin; ti < Context->TpiHeader.TypeIndexEnd; ++ti) {
        if (!KpdbGetTypeRecord(Context, ti, &recLeaf, &pRecData, &recLenData)) {
            continue; // Skip problematic records
        }
        
        // Check if it's a struct, class, or union
        if (recLeaf == LF_STRUCTURE || recLeaf == LF_CLASS || recLeaf == LF_UNION) {
            PCHAR pIter = pRecData;
            PCHAR pEndRecordData = pRecData + recLenData; // End of this specific type record's data
            USHORT count;       // Number of elements in class/struct (not reliable for members count)
            USHORT property;    // CV_prop_t (properties like fwdref, packed, etc.)
            CV_typ_t fieldListTypeIndex;
            CV_typ_t derivedListTypeIndex; // For base classes
            CV_typ_t vShapeTypeIndex;    // For vtable shape
            ULONG aggregateSize;
            LPCSTR currentTypeName;

            // struct LF_CLASS S {
            //    unsigned short  count;      // count of number of elements in class
            //    unsigned short  property;   // property attribute field
            //    CV_typ_t        field;      // type index of LF_FIELDิน
            //    CV_typ_t        derived;    // type index of derived from list if not zero
            //    CV_typ_t        vshape;     // type index of vshape table for this class
            //    unsigned char   data[];     // data bytes consisting of numeric leaf for size
            //                                // of class and name string
            // };
            
            // Bounds checks before dereferencing
            if (pIter + sizeof(USHORT) * 2 + sizeof(CV_typ_t) * 3 > pEndRecordData) continue;

            count = *(USHORT*)pIter; pIter += sizeof(USHORT);
            property = *(USHORT*)pIter; pIter += sizeof(USHORT);
            fieldListTypeIndex = *(CV_typ_t*)pIter; pIter += sizeof(CV_typ_t);
            derivedListTypeIndex = *(CV_typ_t*)pIter; pIter += sizeof(CV_typ_t); // Ignored for now
            vShapeTypeIndex = *(CV_typ_t*)pIter; pIter += sizeof(CV_typ_t);   // Ignored for now

            if (!KpdbReadNumeric(&pIter, pEndRecordData, &aggregateSize)) {
                // DbgPrintEx(0,0, "[KPDB] Could not read size for TI 0x%X.\n", ti);
                continue; // Skip if size can't be read
            }

            currentTypeName = (LPCSTR)pIter;
            // Validate name (is it null-terminated within bounds?)
            size_t nameLenCheck = 0;
            while(pIter + nameLenCheck < pEndRecordData && *(pIter + nameLenCheck) != '\0') {
                nameLenCheck++;
            }
            if (pIter + nameLenCheck >= pEndRecordData) { // Name not null-terminated within record
                 //DbgPrintEx(0,0, "[KPDB] Type name for TI 0x%X not NUL-terminated or too long.\n", ti);
                continue;
            }


            if (strcmp(currentTypeName, TypeName) == 0) {
                PTYPE_AGGREGATE_INFO newParsedInfo = &Context->ParsedAggregates[Context->ParsedAggregateCount];
                RtlZeroMemory(newParsedInfo, sizeof(TYPE_AGGREGATE_INFO));

                strcpy_s(newParsedInfo->Name, sizeof(newParsedInfo->Name), TypeName);
                newParsedInfo->TypeIndex = ti;
                newParsedInfo->Size = aggregateSize;
                newParsedInfo->Kind = (CV_लीफ_e)recLeaf;

                // Check if it has a field list (forward declaration structs might not)
                // CV_prop_fwdref bit in 'property' field indicates a forward reference.
                // Also, fieldListTypeIndex could be 0 (CV_PROC_void for empty list)
                if (fieldListTypeIndex != 0 && !(property & 0x80 /* CV_PROP_FWDREF */)) { 
                    if (!KpdbGetFieldListMembers(Context, fieldListTypeIndex, newParsedInfo)) {
                        // DbgPrintEx(0, 0, "[KPDB] Failed to get members for %s via FieldList 0x%X.\n", TypeName, fieldListTypeIndex);
                        // Still consider type found, but member list might be empty or incomplete
                    }
                } else {
                    // DbgPrintEx(0, 0, "[KPDB] Type %s is a forward reference or has no field list.\n", TypeName);
                    newParsedInfo->MemberCount = 0;
                    newParsedInfo->Members = NULL;
                }

                Context->ParsedAggregateCount++;
                *ppFoundTypeInfo = newParsedInfo;
                return TRUE; // Found
            }
        }
    }

    return FALSE; // Not found
}
