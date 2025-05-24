#include "DriverEntry.h"

// Ensure this is included if not already through kpdb.h or ntutils.h
// This is for DriverEntry and other NTSTATUS codes.
// It's usually pulled in by ntifs.h (via ntutils.h)
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif


LPCSTR WantedSymbolList[] = { 
	"PspLoadImageNotifyRoutine", 
	"PspCreateProcessNotifyRoutine", 
	"PspCreateThreadNotifyRoutine", 
	"CallbackListHead",
	"EtwThreatIntProvRegHandle", 
	"KiServiceTable", 
	"KiTimerDispatch" };

SYMBOL_DATA SymbolsData[MAX_SYMBOL_DATA + 1]; // +1 for null terminator entry if used that way

void KpdbDemoRoutine() {
    SIZE_T FileSize = 0;
    PVOID pdbfile = NULL;
    LPCWSTR pdbfilepath = L"\\??\\C:\\Users\\ZEROBI~1\\AppData\\Local\\Temp\\ida\\ntkrnlmp.pdb\\87A327C6C356B7E2BAC1D75E779701651\\ntkrnlmp.pdb"; // replace this with the path of the PDB (keep the "\\??\\")
    
    // Initialize SymbolData names
	for (int i = 0; i < (sizeof(WantedSymbolList) / sizeof(LPCSTR)); i++) {
		SymbolsData[i].SymbolName = WantedSymbolList[i];
        SymbolsData[i].SectionNumber = 0; // Initialize other fields
        SymbolsData[i].SectionOffset = 0;
        SymbolsData[i].SymbolRVA = 0;
	}
    // Null terminate the list of symbols to search for (if iteration relies on .SymbolName being NULL)
    SymbolsData[sizeof(WantedSymbolList) / sizeof(LPCSTR)].SymbolName = NULL;


	// read PDB file and parse
	DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - Reading NT symbols...\n");
	{
		// get file size
		if (!NT_SUCCESS(UtilGetFileSize(pdbfilepath, NULL, &FileSize, NULL))) {
			DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - UtilGetFileSize failed!\n");
			return;
		}
        if (FileSize == 0) {
            DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - PDB file size is 0.\n");
            return;
        }

		// allocate memory for file
		pdbfile = ExAllocatePool(PagedPool, FileSize);
        if (!pdbfile) {
            DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - ExAllocatePool for PDB file failed!\n");
            return;
        }

		// read file
		if (!NT_SUCCESS(UtilReadFile(pdbfilepath, pdbfile)))
		{
			ExFreePool(pdbfile);
			DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - UtilReadFile failed!\n");
			return;
		}

		// run the symbol parse
		if (!KpdbGetPDBSymbolOffset(pdbfile, SymbolsData)) {
			ExFreePool(pdbfile);
			DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - KpdbGetPDBSymbolOffset failed!\n");
			return;
		}

		// Symbol parsing successful (or partially), now TPI
        DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - Symbol parsing finished. Starting TPI parsing demo...\n");

        // --- Start TPI Parsing Demo ---
        KpdbPDB_CONTEXT pdbContext = { 0 }; // Must be initialized
        if (KpdbInitializeContext(&pdbContext, pdbfile)) {
            DbgPrintEx(0, 0, "[KPDB] TPI Initialized. TypeIndexBegin: %u, TypeIndexEnd: %u, RecordCount: %u\n",
                pdbContext.TpiHeader.TypeIndexBegin, 
                pdbContext.TpiHeader.TypeIndexEnd,
                pdbContext.TypeRecordCount);

            // Example: Try to find info for a type.
            // Common ntoskrnl.exe structs: "_EPROCESS", "_KPROCESS", "_ETHREAD", "_OBJECT_HEADER", "_UNICODE_STRING"
            LPCSTR targetTypeName = "_OBJECT_HEADER"; 
            PTYPE_AGGREGATE_INFO foundType = NULL;

            if (KpdbParseAggregateTypeByName(&pdbContext, targetTypeName, &foundType)) {
                if (foundType) { // Check if pointer is valid
                    DbgPrintEx(0, 0, "[KPDB] Found type: %s (Kind: 0x%X), Size: %u, Members found: %u\n",
                        foundType->Name, foundType->Kind, foundType->Size, foundType->MemberCount);
                    for (USHORT k = 0; k < foundType->MemberCount; ++k) {
                        DbgPrintEx(0, 0, "[KPDB]   Member: %s, Offset: 0x%X (TypeIndex: 0x%X, Attr: 0x%X)\n",
                            foundType->Members[k].Name,
                            foundType->Members[k].Offset,
                            foundType->Members[k].TypeIndex,
                            foundType->Members[k].Attributes);
                    }
                } else {
                     DbgPrintEx(0, 0, "[KPDB] Type '%s' parse returned success but ppFoundTypeInfo is NULL.\n", targetTypeName);
                }
            } else {
                DbgPrintEx(0, 0, "[KPDB] Type '%s' not found or not an aggregate that could be parsed.\n", targetTypeName);
            }

            // Example 2: another common struct
            targetTypeName = "_UNICODE_STRING"; 
            foundType = NULL;
            if (KpdbParseAggregateTypeByName(&pdbContext, targetTypeName, &foundType)) {
                if (foundType) {
                    DbgPrintEx(0, 0, "[KPDB] Found type: %s (Kind: 0x%X), Size: %u, Members found: %u\n",
                        foundType->Name, foundType->Kind, foundType->Size, foundType->MemberCount);
                    for (USHORT k = 0; k < foundType->MemberCount; ++k) {
                        DbgPrintEx(0, 0, "[KPDB]   Member: %s, Offset: 0x%X (TypeIndex: 0x%X, Attr: 0x%X)\n",
                            foundType->Members[k].Name,
                            foundType->Members[k].Offset,
                            foundType->Members[k].TypeIndex,
                            foundType->Members[k].Attributes);
                    }
                }
            } else {
                 DbgPrintEx(0, 0, "[KPDB] Type '%s' not found or not an aggregate that could be parsed.\n", targetTypeName);
            }


            KpdbFreeContext(&pdbContext); // Important to free context resources
        } else {
            DbgPrintEx(0, 0, "[KPDB] Failed to initialize TPI context.\n");
        }
        // --- End TPI Parsing Demo ---


		// free PDB file memory
		ExFreePool(pdbfile);
	} // End of PDB file processing block
    
    // Get kernel base for RVA conversion after PDB file is processed and freed
    ULONG_PTR kernelBase = UtilGetKernelBase();
    if (kernelBase == 0) {
        DbgPrintEx(0,0, "[KPDB] KpdbDemoRoutine - UtilGetKernelBase failed, cannot convert to VA.\n");
    } else {
	    KpdbConvertSecOffsetToRVA(kernelBase, SymbolsData);

	    DWORD Iterator = 0;
	    while (SymbolsData[Iterator].SymbolName && SymbolsData[Iterator].SectionOffset) { // Check SymbolName as well
		    DbgPrintEx(0, 0, "[KPDB] Symbol %s = 0x%p\n", 
                SymbolsData[Iterator].SymbolName, 
                (PVOID)(SymbolsData[Iterator].SymbolRVA + kernelBase) );
		    Iterator++;
	    }
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);
    
    DbgPrintEx(0,0, "[KPDB] DriverEntry called.\n");
	KpdbDemoRoutine();
    DbgPrintEx(0,0, "[KPDB] KpdbDemoRoutine finished. Driver will unload.\n");

	return STATUS_UNSUCCESSFUL; // Return unsuccessful to unload the driver after demo
}
