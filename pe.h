#pragma once
#include <Windows.h>
#include <string>
typedef struct _PEInfo {
	DWORD size_of_code;
	DWORD size_of_image;
	DWORD entry;
	DWORD64 image_base;
}PEInfo;
BOOL PE_MapAndResolve(char* driver_path, DWORD64 target_kernel_addr, HMODULE* module);
bool PE_GetCodeSectionStartOffset(const std::wstring& filePath, DWORD& codeSectionOffset);
VOID PE_GetPEInfo(CHAR* driver_path, PEInfo* peinfo);
VOID GetNecessaryExportFunc();
ULONG_PTR PE_GetProcAddress(
	_In_ ULONG_PTR KernelBase,
	_In_ ULONG_PTR KernelImage,
	_In_ LPCSTR FunctionName
);
BOOL PE_ResolveKrnlImport(_In_ ULONG_PTR Image,
	_In_ ULONG_PTR KernelImage,
	_In_ ULONG_PTR KernelBase
);
BOOL PE_ResolveAllImports(_In_ ULONG_PTR Image);
BOOL PE_ProcessRelocations(_In_ ULONG_PTR Image, _In_ DWORD64 target_base);
BOOL PE_ScanEntryToDriverEntry(
	_In_ ULONG_PTR driver_base,
	_In_ DWORD entry_rva,
	_Out_ PVOID* out_driver_entry,
	_Out_ PVOID* out_mem_ptr,
	_Out_ DWORD64* out_mem_value);
BOOL PE_GetExportOffset(const char* driver_path, const char* func_name, DWORD* out_offset);
BOOL PE_GetExportOffsetFromMemory(PVOID driver_base, const char* func_name, DWORD* out_offset);
BOOL PE_ScanEntryFindSecondCall(
	_In_ ULONG_PTR mapped_base,
	_In_ DWORD entry_rva,
	_In_ DWORD64 target_kernel_addr,
	_Out_ DWORD64* out_call_target);

// Section info for bounds checking
struct PESectionInfo {
	CHAR name[9];  // null-terminated section name
	DWORD rva;
	DWORD virtual_size;
	DWORD raw_size;
	DWORD characteristics;
};

// Get section list from a PE file. Returns number of sections found.
DWORD PE_GetSectionList(const char* driver_path, PESectionInfo* sections, DWORD max_sections);

// Fix all references (both DIR64 relocations and RIP-relative instructions)
// that point into [old_addr, old_addr+size) to point into [new_addr, new_addr+size) instead.
// image_base is the virtual address where the mapped image will run in kernel.
// code_rva/code_size describe the code section to scan for RIP-relative instructions.
BOOL PE_FixRemappedSectionRefs(
	_In_ ULONG_PTR Image,
	_In_ DWORD64 image_base,
	_In_ DWORD code_rva,
	_In_ DWORD code_size,
	_In_ DWORD64 old_addr,
	_In_ DWORD64 old_size,
	_In_ DWORD64 new_addr);
