#pragma once
#include "kpdb.h"
#include "ntutils.h"

#define MAX_SYMBOL_DATA 32 // This is already in kpdb.h, can be removed here if kpdb.h always included first.
                           // Or ensure it matches if defined in both.

// Functions are now part of kpdb.h as well. Redundant here if kpdb.h is included.
// void KpdbDemoRoutine();
// NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
