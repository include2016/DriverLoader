#include "Kernel.h"
#include "MacroDef.h"
#include <winternl.h>

#define SystemModuleInformation 11

#pragma comment(lib, "ntdll.lib")

typedef struct _SYSTEM_MODULE_ENTRY {
	PVOID  Reserved1;
	PVOID  Reserved2;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR   FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

namespace KRNL {
	NTSTATUS GetDriverBase(
		_In_ PCSTR DriverName,
		_Out_ PVOID* DriverBaseAddress
	)
	{
		NTSTATUS status;
		ULONG bufferSize = 0;
		PVOID buffer = NULL;

		*DriverBaseAddress = NULL;

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
			NULL,
			0,
			&bufferSize
		);

		if (status != STATUS_INFO_LENGTH_MISMATCH)
			return status;

		buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
		if (!buffer)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
			buffer,
			bufferSize,
			&bufferSize
		);

		if (0 != status) {
			HeapFree(GetProcessHeap(), 0, buffer);
			return status;
		}

		PSYSTEM_MODULE_INFORMATION pInfo =
			(PSYSTEM_MODULE_INFORMATION)buffer;

		for (ULONG i = 0; i < pInfo->NumberOfModules; i++) {
			PSYSTEM_MODULE_ENTRY pEntry = &pInfo->Modules[i];

			if (_stricmp(
				pEntry->FullPathName + pEntry->OffsetToFileName,
				DriverName
			) == 0)
			{
				*DriverBaseAddress = pEntry->ImageBase;
				break;
			}
		}

		HeapFree(GetProcessHeap(), 0, buffer);
		return (*DriverBaseAddress) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
	}
}
