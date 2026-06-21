#include "pe.h"
#include "ntos.h"
#include "LdrCtx.h"
#include "Log.h"
#include "Helper.h"
#include "Kernel.h"
#include <capstone.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "MacroDef.h"

// Read code from kernel memory and disassemble to find target addresses.
// Step 1: From entry point, find first JMP → that's DriverEntry
// Step 2: From DriverEntry, find first JMP instruction (record its offset from DriverEntry)
// Step 3: From DriverEntry + offset, find first mov [mem], reg
// Step 4: Read 8 bytes from that mem address
BOOL PE_ScanEntryToDriverEntry(
	_In_ ULONG_PTR driver_base,
	_In_ DWORD entry_rva,
	_Out_ PVOID* out_driver_entry,
	_Out_ PVOID* out_mem_ptr,
	_Out_ DWORD64* out_mem_value)
{
	*out_driver_entry = NULL;
	*out_mem_ptr = NULL;
	*out_mem_value = 0;

	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		LDRLog(L"PE_ScanEntryToDriverEntry: cs_open failed\n");
		return FALSE;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	ULONG_PTR entry_addr = driver_base + entry_rva;

	// Step 1: Read code from entry point, find first JMP
	UCHAR code_buf[256] = { 0 };
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)entry_addr, code_buf, sizeof(code_buf))) {
		LDRLog(L"PE_ScanEntryToDriverEntry: failed to read entry point code\n");
		cs_close(&handle);
		return FALSE;
	}

	ULONG_PTR driver_entry = 0;
	cs_insn* insn = NULL;
	size_t count = cs_disasm(handle, code_buf, sizeof(code_buf), entry_addr, 32, &insn);
	if (count == 0) {
		LDRLog(L"PE_ScanEntryToDriverEntry: cs_disasm failed at entry\n");
		cs_close(&handle);
		return FALSE;
	}

	for (size_t i = 0; i < count; i++) {
		if (insn[i].id == X86_INS_JMP) {
			// Resolve JMP target (RIP-relative)
			ULONG_PTR target = 0;
			if (insn[i].detail->x86.op_count > 0) {
				cs_x86_op* op = &insn[i].detail->x86.operands[0];
				if (op->type == X86_OP_IMM) {
					target = op->imm;
				}
			}
			if (target != 0) {
				driver_entry = target;
				LDRLog(L"Step1: JMP at 0x%llX -> DriverEntry=0x%llX\n",
					(ULONG_PTR)insn[i].address, driver_entry);
			}
			break;
		}
	}
	cs_free(insn, count);

	if (driver_entry == 0) {
		LDRLog(L"PE_ScanEntryToDriverEntry: no JMP found at entry point\n");
		cs_close(&handle);
		return FALSE;
	}

	// Step 2: From DriverEntry, find first JMP instruction, record offset from DriverEntry
	UCHAR de_buf[512] = { 0 };
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)driver_entry, de_buf, sizeof(de_buf))) {
		LDRLog(L"PE_ScanEntryToDriverEntry: failed to read DriverEntry code\n");
		cs_close(&handle);
		return FALSE;
	}

	DWORD jmp_offset_from_de = 0;
	count = cs_disasm(handle, de_buf, sizeof(de_buf), driver_entry, 64, &insn);
	if (count == 0) {
		LDRLog(L"PE_ScanEntryToDriverEntry: cs_disasm failed at DriverEntry\n");
		cs_close(&handle);
		return FALSE;
	}

	for (size_t i = 0; i < count; i++) {
		if (insn[i].id == X86_INS_JMP || insn[i].id == X86_INS_JE ||
			insn[i].id == X86_INS_JNE || insn[i].id == X86_INS_JB ||
			insn[i].id == X86_INS_JBE || insn[i].id == X86_INS_JA || insn[i].id == X86_INS_JAE || insn[i].id == X86_INS_JG || insn[i].id == X86_INS_JGE || insn[i].id == X86_INS_JL || insn[i].id == X86_INS_JLE || insn[i].id == X86_INS_JECXZ || insn[i].id == X86_INS_JRCXZ) {
			// Any jump instruction - record offset from DriverEntry
			jmp_offset_from_de = (DWORD)(insn[i].address - driver_entry);
			LDRLog(L"Step2: JMP at offset 0x%x from DriverEntry (addr=0x%llX)\n",
				jmp_offset_from_de, (ULONG_PTR)insn[i].address);
			break;
		}
	}
	cs_free(insn, count);

	if (jmp_offset_from_de == 0) {
		LDRLog(L"PE_ScanEntryToDriverEntry: no JMP found in DriverEntry\n");
		cs_close(&handle);
		return FALSE;
	}

	// Step 3: From DriverEntry + jmp_offset, find first mov [mem], reg
	ULONG_PTR scan_addr = driver_entry + jmp_offset_from_de;
	UCHAR scan_buf[512] = { 0 };
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)scan_addr, scan_buf, sizeof(scan_buf))) {
		LDRLog(L"PE_ScanEntryToDriverEntry: failed to read code at scan_addr\n");
		cs_close(&handle);
		return FALSE;
	}

	ULONG_PTR mem_addr = 0;
	count = cs_disasm(handle, scan_buf, sizeof(scan_buf), scan_addr, 64, &insn);
	if (count == 0) {
		LDRLog(L"PE_ScanEntryToDriverEntry: cs_disasm failed at scan_addr\n");
		cs_close(&handle);
		return FALSE;
	}

	for (size_t i = 0; i < count; i++) {
		if (insn[i].id == X86_INS_MOV && insn[i].detail->x86.op_count >= 2) {
			cs_x86_op* dst = &insn[i].detail->x86.operands[0];
			cs_x86_op* src = &insn[i].detail->x86.operands[1];
			// dst must be memory, src must be register
			if (dst->type == X86_OP_MEM && src->type == X86_OP_REG) {
				// Resolve memory address: base + index*scale + disp
				// For mov [rip+disp], reg: base=rip(end of this insn), disp=displacement
				ULONG_PTR base = 0;
				if (dst->mem.base == X86_REG_RIP) {
					base = insn[i].address + insn[i].size;
				} else if (dst->mem.base == 0) {
					base = 0;
				} else {
					// Other base register - can't resolve at this point
					continue;
				}
				mem_addr = base + dst->mem.disp;
				LDRLog(L"Step3: mov [mem],reg at 0x%llX -> mem_addr=0x%llX\n",
					(ULONG_PTR)insn[i].address, mem_addr);
				break;
			}
		}
	}
	cs_free(insn, count);
	cs_close(&handle);

	if (mem_addr == 0) {
		LDRLog(L"PE_ScanEntryToDriverEntry: no mov [mem],reg found\n");
		return FALSE;
	}

	// Step 4: Read 8 bytes from mem_addr
	DWORD64 value = 0;
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)mem_addr, &value, sizeof(DWORD64))) {
		LDRLog(L"PE_ScanEntryToDriverEntry: failed to read 8 bytes from mem_addr\n");
		return FALSE;
	}
	LDRLog(L"Step4: read 8 bytes from 0x%llX = 0x%llX\n", mem_addr, value);

	*out_driver_entry = (PVOID)driver_entry;
	*out_mem_ptr = (PVOID)mem_addr;
	*out_mem_value = value;
	return TRUE;
}

// Scan the mapped source driver's entry point to find the 2nd CALL instruction target.
// The mapped image has been relocated to target_kernel_addr, so all RIP-relative offsets
// are correct for that base. However, Capstone resolves CALL targets using the mapped
// base address, so we convert the result back to an RVA and recalculate with
// target_kernel_addr to get the correct kernel absolute address.
BOOL PE_ScanEntryFindSecondCall(
	_In_ ULONG_PTR mapped_base,
	_In_ DWORD entry_rva,
	_In_ DWORD64 target_kernel_addr,
	_Out_ DWORD64* out_call_target)
{
	*out_call_target = 0;

	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		LDRLog(L"PE_ScanEntryFindSecondCall: cs_open failed\n");
		return FALSE;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	// Read from mapped user memory (not kernel memory), so no LdrCtx_GetKpTable()->ReadPrimitive needed
	ULONG_PTR entry_addr = mapped_base + entry_rva;
	UCHAR* code_ptr = (UCHAR*)entry_addr;

	cs_insn* insn = NULL;
	size_t count = cs_disasm(handle, code_ptr, 256, entry_addr, 64, &insn);
	if (count == 0) {
		LDRLog(L"PE_ScanEntryFindSecondCall: cs_disasm failed at entry\n");
		cs_close(&handle);
		return FALSE;
	}

	int call_index = 0;
	DWORD64 call_target_mapped = 0; // target in mapped (user-space) address space
	for (size_t i = 0; i < count; i++) {
		if (insn[i].id == X86_INS_CALL) {
			call_index++;
			if (call_index == 2) {
				if (insn[i].detail->x86.op_count > 0) {
					cs_x86_op* op = &insn[i].detail->x86.operands[0];
					if (op->type == X86_OP_IMM) {
						call_target_mapped = (DWORD64)op->imm;
					} else if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
						ULONG_PTR rip_after = insn[i].address + insn[i].size;
						call_target_mapped = rip_after + op->mem.disp;
					}
				}
				LDRLog(L"PE_ScanEntryFindSecondCall: 2nd CALL at 0x%llX -> mapped_target=0x%llX\n",
					(ULONG_PTR)insn[i].address, call_target_mapped);
				break;
			}
		}
	}
	cs_free(insn, count);
	cs_close(&handle);

	if (call_target_mapped == 0) {
		LDRLog(L"PE_ScanEntryFindSecondCall: 2nd CALL not found\n");
		return FALSE;
	}

	// Convert mapped address to RVA, then to kernel address using target_kernel_addr
	DWORD64 rva = call_target_mapped - (DWORD64)mapped_base;
	DWORD64 call_target_kernel = target_kernel_addr + rva;
	*out_call_target = call_target_kernel;
	LDRLog(L"PE_ScanEntryFindSecondCall: hook_code_addr=0x%llX (rva=0x%llX, target_kernel_addr=0x%llX)\n",
		call_target_kernel, rva, target_kernel_addr);
	return TRUE;
}

BOOL PE_PatchExportFuncSecondCall(
	_In_ ULONG_PTR mapped_base,
	_In_ const char* driver_path,
	_In_ const char* func_name)
{
	DWORD func_rva = 0;
	if (!PE_GetExportOffset(driver_path, func_name, &func_rva)) {
		LDRLog(L"PE_PatchExportFuncSecondCall: failed to find export [%S] in [%S]\n", func_name, driver_path);
		return FALSE;
	}

	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		LDRLog(L"PE_PatchExportFuncSecondCall: cs_open failed\n");
		return FALSE;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	ULONG_PTR func_addr = mapped_base + func_rva;
	UCHAR* code_ptr = (UCHAR*)func_addr;

	cs_insn* insn = NULL;
	size_t count = cs_disasm(handle, code_ptr, 256, func_addr, 64, &insn);
	if (count == 0) {
		LDRLog(L"PE_PatchExportFuncSecondCall: cs_disasm failed at %S\n", func_name);
		cs_close(&handle);
		return FALSE;
	}

	int call_index = 0;
	DWORD64 call_target_mapped = 0;
	for (size_t i = 0; i < count; i++) {
		if (insn[i].id == X86_INS_CALL) {
			call_index++;
			if (call_index == 2) {
				if (insn[i].detail->x86.op_count > 0) {
					cs_x86_op* op = &insn[i].detail->x86.operands[0];
					if (op->type == X86_OP_IMM) {
						call_target_mapped = (DWORD64)op->imm;
					} else if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
						ULONG_PTR rip_after = insn[i].address + insn[i].size;
						call_target_mapped = rip_after + op->mem.disp;
					}
				}
				LDRLog(L"PE_PatchExportFuncSecondCall: 2nd CALL in [%S] -> target=0x%llX\n",
					func_name, call_target_mapped);
				break;
			}
		}
	}
	cs_free(insn, count);
	cs_close(&handle);

	if (call_target_mapped == 0) {
		LDRLog(L"PE_PatchExportFuncSecondCall: 2nd CALL target not found in [%S]\n", func_name);
		return FALSE;
	}

	// Overwrite the target function's first byte with RET (0xC3)
	DWORD64 target_offset = call_target_mapped - (DWORD64)mapped_base;
	UCHAR* target_ptr = (UCHAR*)mapped_base + target_offset;
	*target_ptr = 0xC3;
	LDRLog(L"PE_PatchExportFuncSecondCall: patched target at rva=0x%llX with RET in mapped image\n",
		target_offset);

	return TRUE;
}

DWORD PE_GetSectionList(const char* driver_path, PESectionInfo* sections, DWORD max_sections)
{
	std::ifstream file(driver_path, std::ios::binary);
	if (!file.is_open()) {
		LDRLog(L"PE_GetSectionList: failed to open %S\n", driver_path);
		return 0;
	}

	IMAGE_DOS_HEADER dos{};
	file.read((char*)&dos, sizeof(dos));
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

	file.seekg(dos.e_lfanew, std::ios::beg);

	DWORD signature = 0;
	file.read((char*)&signature, sizeof(signature));
	if (signature != IMAGE_NT_SIGNATURE) return 0;

	IMAGE_FILE_HEADER fileHeader{};
	file.read((char*)&fileHeader, sizeof(fileHeader));

	// Skip optional header
	WORD optSize = fileHeader.SizeOfOptionalHeader;
	file.seekg(optSize, std::ios::cur);

	DWORD count = (fileHeader.NumberOfSections < max_sections)
		? fileHeader.NumberOfSections : max_sections;

	for (DWORD i = 0; i < count; i++) {
		IMAGE_SECTION_HEADER sec{};
		file.read((char*)&sec, sizeof(sec));
		memcpy(sections[i].name, sec.Name, 8);
		sections[i].name[8] = '\0';
		sections[i].rva = sec.VirtualAddress;
		sections[i].virtual_size = sec.Misc.VirtualSize;
		sections[i].raw_size = sec.SizeOfRawData;
		sections[i].characteristics = sec.Characteristics;
	}

	return count;
}

VOID PE_GetPEInfo(CHAR* driver_path, PEInfo* peinfo)
{
	std::ifstream file(driver_path, std::ios::binary);
	if (!file.is_open()) {
		LDRLog(L"Failed to open file: %S\n", driver_path);
		return;
	}

	IMAGE_DOS_HEADER dos{};
	file.read((char*)&dos, sizeof(dos));
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
		LDRLog(L"Invalid DOS header\n");
		return;
	}

	file.seekg(dos.e_lfanew, std::ios::beg);

	DWORD signature = 0;
	file.read((char*)&signature, sizeof(signature));
	if (signature != IMAGE_NT_SIGNATURE) {
		LDRLog(L"Invalid NT signature\n");
		return;
	}

	IMAGE_FILE_HEADER fileHeader{};
	file.read((char*)&fileHeader, sizeof(fileHeader));

	if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
		LDRLog(L"Optional header too small\n");
		return;
	}

	IMAGE_OPTIONAL_HEADER64 optional{};
	file.read((char*)&optional, sizeof(optional));

	peinfo->size_of_code = optional.SizeOfCode;
	peinfo->size_of_image = optional.SizeOfImage;
	peinfo->entry = optional.AddressOfEntryPoint;
	peinfo->image_base = optional.ImageBase;
}


ULONG_PTR PE_GetProcAddress(
	_In_ ULONG_PTR KernelBase,
	_In_ ULONG_PTR KernelImage,
	_In_ LPCSTR FunctionName
)
{
	ANSI_STRING    cStr;
	ULONG_PTR      pfn = 0;

	RtlInitString(&cStr, FunctionName);
	if (!NT_SUCCESS(LdrGetProcedureAddress((PVOID)KernelImage, &cStr, 0, (PVOID*)&pfn)))
		return 0;

	return KernelBase + (pfn - KernelImage);
}
BOOL PE_ResolveKrnlImport(_In_ ULONG_PTR Image,
		_In_ ULONG_PTR KernelImage,
		_In_ ULONG_PTR KernelBase
	)
	{
		PIMAGE_OPTIONAL_HEADER      popth;
		ULONG_PTR                   ITableVA, *nextthunk;
		PIMAGE_IMPORT_DESCRIPTOR    ITable;
		PIMAGE_THUNK_DATA           pthunk;
		PIMAGE_IMPORT_BY_NAME       pname;
		ULONG                       i;

		popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

		if (popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
			return FALSE;

		ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (ITableVA == 0)
			return FALSE;

		ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);

		if (ITable->OriginalFirstThunk == 0)
			pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
		else
			pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

		for (i = 0; pthunk->u1.Function != 0; i++, pthunk++) {
			nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);
			if ((pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
				pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + pthunk->u1.AddressOfData);
				nextthunk[i] = PE_GetProcAddress(KernelBase, KernelImage, pname->Name);
			}
			else
				nextthunk[i] = PE_GetProcAddress(KernelBase, KernelImage, (LPCSTR)(pthunk->u1.Ordinal & 0xffff));
		}
		return TRUE;
}
// Resolve all imports: walk every import descriptor, load the corresponding DLL,
// look up each imported function, and fill IAT with kernel-space absolute addresses.
BOOL PE_ResolveAllImports(_In_ ULONG_PTR Image) {
	PIMAGE_OPTIONAL_HEADER      popth;
	ULONG_PTR                   ITableVA, *nextthunk;
	PIMAGE_IMPORT_DESCRIPTOR    ITable;
	PIMAGE_THUNK_DATA           pthunk;
	PIMAGE_IMPORT_BY_NAME       pname;
	ULONG                       i;

	popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

	if (popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
		return FALSE;

	ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (ITableVA == 0)
		return FALSE;

	ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);

	for (; ITable->Name != 0; ITable++) {
		// Get the DLL name from the import descriptor
		CHAR* dll_name = (CHAR*)(Image + ITable->Name);

		// Step 1: Get kernel base address
		PVOID kernel_base = NULL;
		NTSTATUS krnl_st = KRNL::GetDriverBase(dll_name, &kernel_base);
		if (0 != krnl_st || kernel_base == NULL) {
			LDRLog(L"PE_ResolveAllImports: failed to get kernel base for [%S], Status=0x%x\n", dll_name, krnl_st);
			continue;
		}

		// Step 2: Locate the DLL file on disk for export parsing
		CHAR file_path[MAX_PATH] = { 0 };
		BOOL file_found = FALSE;

		// Try current directory
		sprintf_s(file_path, MAX_PATH, "%s", dll_name);
		if (GetFileAttributesA(file_path) != INVALID_FILE_ATTRIBUTES) {
			file_found = TRUE;
		}
		// Try System32\drivers
		if (!file_found) {
			sprintf_s(file_path, MAX_PATH, "C:\\Windows\\System32\\drivers\\%s", dll_name);
			if (GetFileAttributesA(file_path) != INVALID_FILE_ATTRIBUTES) {
				file_found = TRUE;
			}
		}
		// Try System32
		if (!file_found) {
			sprintf_s(file_path, MAX_PATH, "C:\\Windows\\System32\\%s", dll_name);
			if (GetFileAttributesA(file_path) != INVALID_FILE_ATTRIBUTES) {
				file_found = TRUE;
			}
		}

		// Walk the thunks for this import descriptor
		PIMAGE_THUNK_DATA orig_thunk;
		if (ITable->OriginalFirstThunk == 0)
			orig_thunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
		else
			orig_thunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

		nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);

		for (i = 0; orig_thunk[i].u1.Function != 0; i++) {
			if ((orig_thunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
				pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + orig_thunk[i].u1.AddressOfData);

				DWORD func_offset = 0;
				BOOL resolved = FALSE;

				// Resolve by parsing PE exports from the file on disk
				if (file_found && PE_GetExportOffset(file_path, pname->Name, &func_offset) && func_offset != 0) {
					resolved = TRUE;
				}
				// Fall back to kernel memory export parsing
				else if (PE_GetExportOffsetFromMemory(kernel_base, pname->Name, &func_offset) && func_offset != 0) {
					LDRLog(L"failed to resolve export function from disk file \n");
					resolved = TRUE;
				}

				if (resolved) {
					nextthunk[i] = (ULONG_PTR)kernel_base + func_offset;
				} else {
					LDRLog(L"PE_ResolveAllImports: failed to resolve [%S]!%S\n", dll_name, pname->Name);
					nextthunk[i] = 0;
				}
			} else {
				// Import by ordinal — not supported with PE export parsing
				USHORT ordinal = (USHORT)(orig_thunk[i].u1.Ordinal & 0xffff);
				LDRLog(L"PE_ResolveAllImports: ordinal import not supported for [%S] ordinal %u\n", dll_name, ordinal);
				nextthunk[i] = 0;
			}
		}

		LDRLog(L"PE_ResolveAllImports: resolved [%S] (%u functions)\n", dll_name, i);
	}
	return TRUE;
}

// Process PE relocations so the image can run at target_base instead of its preferred ImageBase.
// delta = target_base - original ImageBase; walk the .reloc section and apply fixups.
BOOL PE_ProcessRelocations(_In_ ULONG_PTR Image, _In_ DWORD64 target_base) {
	PIMAGE_NT_HEADERS nt = RtlImageNtHeader((PVOID)Image);
	if (!nt) {
		LDRLog(L"PE_ProcessRelocations: RtlImageNtHeader failed\n");
		return FALSE;
	}

	DWORD64 preferred_base = nt->OptionalHeader.ImageBase;
	LONGLONG delta = (LONGLONG)(target_base - preferred_base);
	if (delta == 0) {
		LDRLog(L"PE_ProcessRelocations: delta=0, no fixup needed\n");
		return TRUE;
	}

	if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		LDRLog(L"PE_ProcessRelocations: no reloc directory\n");
		return TRUE;
	}

	DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (reloc_rva == 0 || reloc_size == 0) {
		LDRLog(L"PE_ProcessRelocations: reloc table is empty\n");
		return TRUE;
	}

	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(Image + reloc_rva);
	DWORD bytes_remaining = reloc_size;

	while (bytes_remaining > 0) {
		if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
			LDRLog(L"PE_ProcessRelocations: invalid reloc block size\n");
			break;
		}

		DWORD num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD entries = (PWORD)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < num_entries; i++) {
			WORD type = entries[i] >> 12;
			WORD offset = entries[i] & 0x0FFF;

			if (type == IMAGE_REL_BASED_DIR64) {
				DWORD64* patch_addr = (DWORD64*)(Image + reloc->VirtualAddress + offset);
				DWORD64 old_val = *patch_addr;
			*patch_addr += delta;
			LDRLog(L"  DIR64 @ rva=0x%x: 0x%llX -> 0x%llX (delta=0x%llX)\n",
				reloc->VirtualAddress + offset, old_val, *patch_addr, delta);
			} else if (type == IMAGE_REL_BASED_ABSOLUTE) {
				// Skip padding entries
			} else {
				LDRLog(L"PE_ProcessRelocations: unsupported reloc type %u at offset 0x%x\n", type, offset);
			}
		}

		bytes_remaining -= reloc->SizeOfBlock;
		reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
	}

	LDRLog(L"PE_ProcessRelocations: done, delta=0x%llX, target_base=0x%llX\n", delta, target_base);
	return TRUE;
}

BOOL PE_FixRemappedSectionRefs(
	_In_ ULONG_PTR Image,
	_In_ DWORD64 image_base,
	_In_ DWORD code_rva,
	_In_ DWORD code_size,
	_In_ const PESectionRemap* remaps,
	_In_ DWORD remap_count)
{
	PIMAGE_NT_HEADERS nt = RtlImageNtHeader((PVOID)Image);
	if (!nt) {
		LDRLog(L"PE_FixRemappedSectionRefs: RtlImageNtHeader failed\n");
		return FALSE;
	}

	DWORD reloc_fix = 0;
	DWORD rip_fix = 0;

	// Helper: find which remap entry a target address falls into, or -1
	auto find_remap = [&](DWORD64 target) -> int {
		for (DWORD r = 0; r < remap_count; r++) {
			if (target >= remaps[r].old_addr && target < remaps[r].old_addr + remaps[r].old_size)
				return (int)r;
		}
		return -1;
	};

	// Part 1: Fix DIR64 relocations that point into any remapped writable section range
	// Scan ALL reloc entries regardless of which section they reside in.
	if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if (reloc_rva != 0 && reloc_size != 0) {
			PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(Image + reloc_rva);
			DWORD bytes_remaining = reloc_size;

			while (bytes_remaining > 0) {
				if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
					break;
				DWORD block_rva = reloc->VirtualAddress;
				DWORD num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				PWORD entries = (PWORD)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

				for (DWORD i = 0; i < num_entries; i++) {
					WORD type = entries[i] >> 12;
					WORD offset = entries[i] & 0x0FFF;
					if (type == IMAGE_REL_BASED_DIR64) {
						DWORD64* p = (DWORD64*)(Image + block_rva + offset);
						DWORD64 val = *p;
						int r = find_remap(val);
						if (r >= 0) {
							LONGLONG adjust = (LONGLONG)(remaps[r].new_addr - remaps[r].old_addr);
							*p = (DWORD64)((LONGLONG)val + adjust);
							reloc_fix++;
						}
					}
				}

				bytes_remaining -= reloc->SizeOfBlock;
				reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
			}
		}
	}

	// Part 2: Fix RIP-relative instructions in code section that reference any remapped writable section
	if (code_rva != 0 && code_size != 0) {
		csh handle;
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
			cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
				cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

			UCHAR* code = (UCHAR*)(Image + code_rva);
			size_t code_len = code_size;
			DWORD64 base_addr = image_base + code_rva;

			cs_insn* insn = NULL;
			size_t count = cs_disasm(handle, code, code_len, base_addr, 0, &insn);

			for (size_t i = 0; i < count; i++) {
				cs_detail* d = insn[i].detail;
				if (!d) continue;

				for (int j = 0; j < d->x86.op_count; j++) {
					cs_x86_op* op = &d->x86.operands[j];
					if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
						DWORD64 target = insn[i].address + insn[i].size + op->mem.disp;
						int r = find_remap(target);
						if (r >= 0) {
							LONGLONG adjust = (LONGLONG)(remaps[r].new_addr - remaps[r].old_addr);
							LONGLONG new_target = (LONGLONG)target + adjust;
							LDRLog(L"  RIP-relative @ rva=0x%llX: target 0x%llX -> 0x%llX (remap[%d])\n",
								insn[i].address - image_base, target, (DWORD64)new_target, r);
							LONGLONG new_disp = new_target - (LONGLONG)(insn[i].address + insn[i].size);
							if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
								LDRLog(L"PE_FixRemappedSectionRefs: disp overflow at 0x%llX (new_disp=0x%llX)\n",
									insn[i].address, new_disp);
								continue;
							}
							DWORD insn_offset = (DWORD)(insn[i].address - base_addr);
							DWORD disp_offset = insn_offset + (DWORD)(d->x86.encoding.disp_offset);
							if (d->x86.encoding.disp_size != 4) continue;
							INT32* p_disp = (INT32*)(code + disp_offset);
							*p_disp = (INT32)new_disp;
							rip_fix++;
						}
					}
				}
			}

			if (insn) cs_free(insn, count);
			cs_close(&handle);
		}
	}

	LDRLog(L"PE_FixRemappedSectionRefs: reloc_fix=%u rip_fix=%u, remap_count=%u\n",
		reloc_fix, rip_fix, remap_count);
	return TRUE;
}

BOOL PE_MapAndResolve(char* driver_path, DWORD64 target_kernel_addr, HMODULE* module) {
	WCHAR w_driver_path[MAX_PATH] = { 0 };
	Helper::ConvertCharToWchar(driver_path, w_driver_path, MAX_PATH);

	HMODULE            Image = NULL;
	ULONG              DllCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
	UNICODE_STRING     uStr;
	RtlSecureZeroMemory(&uStr, sizeof(uStr));
	RtlInitUnicodeString(&uStr, w_driver_path);
	NTSTATUS status = LdrLoadDll(NULL, &DllCharacteristics, &uStr, (PVOID*)&Image);
	if (0 != status) {
		LDRLog(L"failed to call LdrLoadDLL to load target driver, Status=0x%x\n", status);
		return FALSE;
	}

	PEInfo target_peinfo = { 0 };
	PE_GetPEInfo(driver_path, &target_peinfo);

	// copy into a writable memory
	UCHAR* writable_mem = (UCHAR*)malloc(target_peinfo.size_of_image);
	DWORD proctect_old = 0;
	for (size_t i = 0; i < target_peinfo.size_of_image; i++)
		writable_mem[i] = *((UCHAR*)Image+i);

	*module =(HMODULE)(ULONG_PTR) writable_mem;

	// Fix import table (all DLLs, not just ntoskrnl)
	if (!PE_ResolveAllImports((ULONG_PTR)writable_mem)) {
		LDRLog(L"failed to resolve all imports\n");
		return FALSE;
	}

	// Fix relocations: code will run at target_kernel_addr in kernel
	if (!PE_ProcessRelocations((ULONG_PTR)writable_mem, target_kernel_addr)) {
		LDRLog(L"failed to process relocations\n");
		return FALSE;
	}

	return TRUE;
}
bool PE_GetCodeSectionStartOffset(const std::wstring& filePath, DWORD& codeSectionOffset) {
	std::ifstream file(filePath, std::ios::binary);

	if (!file.is_open()) {
		std::wcerr << L"Failed to open the file, Error=0x" << std::hex << GetLastError() << L"\n";
		return false;
	}

	// Read DOS header
	IMAGE_DOS_HEADER dosHeader;
	file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		std::wcerr << L"Invalid DOS header signature\n";
		return false;
	}

	// Seek to PE header location
	file.seekg(dosHeader.e_lfanew, std::ios::beg);

	// Read the PE signature
	DWORD peSignature;
	file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));

	if (peSignature != IMAGE_NT_SIGNATURE) {
		std::wcerr << L"Invalid PE signature\n";
		return false;
	}

	// Read the NT headers (File Header)
	IMAGE_FILE_HEADER fileHeader;
	file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

	// Check if the PE is 32-bit or 64-bit
	bool isPE32Plus = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || fileHeader.Machine == IMAGE_FILE_MACHINE_ARM64);

	// Now, read the Optional Header based on the PE file type (PE32 vs PE32+)
	if (isPE32Plus) {
		IMAGE_OPTIONAL_HEADER64 optionalHeader;
		file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));

		// Retrieve the BaseOfCode for PE32+ (64-bit)
		codeSectionOffset = optionalHeader.BaseOfCode;
	}
	else {
		IMAGE_OPTIONAL_HEADER32 optionalHeader;
		file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));

		// Retrieve the BaseOfCode for PE32 (32-bit)
		codeSectionOffset = optionalHeader.BaseOfCode;
	}

	return true;
}

VOID GetNecessaryExportFunc() {
	ANSI_STRING        routineName;
	RtlInitString(&routineName, "ZwClose");
	PVOID pfn_ZwClose = NULL;
	NTSTATUS status = LdrGetProcedureAddress((PVOID)LdrCtx_GetKrnlBase(), &routineName, 0, (PVOID*)&pfn_ZwClose);
	if (0 != status) {
		LDRLog(L"failed to get ZwClose function addr, Status=0x%x\n", status);
		return;
	}

	RtlInitString(&routineName, "ExAllocatePoolWithTag");
	PVOID pfn_ExAllocatePoolWithTag = NULL;
	status = LdrGetProcedureAddress((PVOID)LdrCtx_GetKrnlBase(), &routineName, 0, (PVOID*)&pfn_ExAllocatePoolWithTag);
	if (0 != status) {
		LDRLog(L"failed to get ExAllocatePoolWithTag function addr, Status=0x%x\n", status);
		return;
	}

	RtlInitString(&routineName, "PsCreateSystemThread");
	PVOID pfn_PsCreateSystemThread = NULL;
	status = LdrGetProcedureAddress((PVOID)LdrCtx_GetKrnlBase(), &routineName, 0, (PVOID*)&pfn_PsCreateSystemThread);
	if (0 != status) {
		LDRLog(L"failed to get PsCreateSystemThread function addr, Status=0x%x\n", status);
		return;
	}
}

BOOL PE_GetExportOffset(const char* driver_path, const char* func_name, DWORD* out_offset) {
	std::ifstream file(driver_path, std::ios::binary);
	if (!file.is_open()) {
		LDRLog(L"PE_GetExportOffset: failed to open file\n");
		return FALSE;
	}

	IMAGE_DOS_HEADER dos{};
	file.read((char*)&dos, sizeof(dos));
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
		LDRLog(L"PE_GetExportOffset: invalid DOS header\n");
		return FALSE;
	}

	file.seekg(dos.e_lfanew, std::ios::beg);

	DWORD signature = 0;
	file.read((char*)&signature, sizeof(signature));
	if (signature != IMAGE_NT_SIGNATURE) {
		LDRLog(L"PE_GetExportOffset: invalid NT signature\n");
		return FALSE;
	}

	IMAGE_FILE_HEADER fileHeader{};
	file.read((char*)&fileHeader, sizeof(fileHeader));

	IMAGE_OPTIONAL_HEADER64 optional{};
	file.read((char*)&optional, sizeof(optional));

	if (optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
		LDRLog(L"PE_GetExportOffset: no export directory\n");
		return FALSE;
	}

	DWORD export_dir_rva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD export_dir_size = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (export_dir_rva == 0) {
		LDRLog(L"PE_GetExportOffset: export dir RVA is 0\n");
		return FALSE;
	}

	// Read section headers to convert RVA to file offset
	std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
	file.read((char*)sections.data(), sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections);

	auto rvaToFileOffset = [&](DWORD rva) -> DWORD {
		for (auto& sec : sections) {
			if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.Misc.VirtualSize) {
				return rva - sec.VirtualAddress + sec.PointerToRawData;
			}
		}
		return 0;
	};

	DWORD export_dir_file_offset = rvaToFileOffset(export_dir_rva);
	if (export_dir_file_offset == 0) {
		LDRLog(L"PE_GetExportOffset: failed to convert export dir RVA to file offset\n");
		return FALSE;
	}

	// Read export directory
	file.seekg(export_dir_file_offset, std::ios::beg);
	IMAGE_EXPORT_DIRECTORY exportDir{};
	file.read((char*)&exportDir, sizeof(exportDir));

	DWORD names_file_offset = rvaToFileOffset(exportDir.AddressOfNames);
	DWORD ordinals_file_offset = rvaToFileOffset(exportDir.AddressOfNameOrdinals);
	DWORD functions_file_offset = rvaToFileOffset(exportDir.AddressOfFunctions);

	if (names_file_offset == 0 || ordinals_file_offset == 0 || functions_file_offset == 0) {
		LDRLog(L"PE_GetExportOffset: failed to convert export table RVAs to file offsets\n");
		return FALSE;
	}

	// Search for the function name
	for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
		DWORD name_rva = 0;
		file.seekg(names_file_offset + i * sizeof(DWORD), std::ios::beg);
		file.read((char*)&name_rva, sizeof(DWORD));

		DWORD name_file_offset = rvaToFileOffset(name_rva);
		file.seekg(name_file_offset, std::ios::beg);

		char name[256] = { 0 };
		file.read(name, 255);

		if (strcmp(name, func_name) == 0) {
			WORD ordinal = 0;
			file.seekg(ordinals_file_offset + i * sizeof(WORD), std::ios::beg);
			file.read((char*)&ordinal, sizeof(WORD));

			DWORD func_rva = 0;
			file.seekg(functions_file_offset + ordinal * sizeof(DWORD), std::ios::beg);
			file.read((char*)&func_rva, sizeof(DWORD));

			*out_offset = func_rva;
			return TRUE;
		}
	}

	LDRLog(L"PE_GetExportOffset: export function %S not found\n", func_name);
	return FALSE;
}

BOOL PE_GetExportOffsetFromMemory(PVOID driver_base, const char* func_name, DWORD* out_offset) {
	// Read DOS header from kernel memory
	IMAGE_DOS_HEADER dos = { 0 };
	if (!LdrCtx_GetKpTable()->ReadPrimitive(driver_base, &dos, sizeof(dos))) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read DOS header\n");
		return FALSE;
	}
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
		LDRLog(L"PE_GetExportOffsetFromMemory: invalid DOS signature\n");
		return FALSE;
	}

	// Read NT headers
	DWORD64 nt_header_addr = (DWORD64)driver_base + dos.e_lfanew;
	DWORD signature = 0;
	IMAGE_FILE_HEADER fileHeader = { 0 };
	IMAGE_OPTIONAL_HEADER64 optional = { 0 };

	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)nt_header_addr, &signature, sizeof(DWORD))) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read PE signature\n");
		return FALSE;
	}
	if (signature != IMAGE_NT_SIGNATURE) {
		LDRLog(L"PE_GetExportOffsetFromMemory: invalid PE signature\n");
		return FALSE;
	}

	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)(nt_header_addr + sizeof(DWORD)), &fileHeader, sizeof(fileHeader))) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read file header\n");
		return FALSE;
	}

	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)(nt_header_addr + sizeof(DWORD) + sizeof(fileHeader)), &optional, sizeof(optional))) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read optional header\n");
		return FALSE;
	}

	if (optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
		LDRLog(L"PE_GetExportOffsetFromMemory: no export directory\n");
		return FALSE;
	}

	DWORD export_dir_rva = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (export_dir_rva == 0) {
		LDRLog(L"PE_GetExportOffsetFromMemory: export dir RVA is 0\n");
		return FALSE;
	}

	// Read export directory from kernel memory
	IMAGE_EXPORT_DIRECTORY exportDir = { 0 };
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)((DWORD64)driver_base + export_dir_rva), &exportDir, sizeof(exportDir))) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read export directory\n");
		return FALSE;
	}

	// Read name pointers (RVAs of export names)
	DWORD* name_rvas = (DWORD*)malloc(sizeof(DWORD) * exportDir.NumberOfNames);
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)((DWORD64)driver_base + exportDir.AddressOfNames),
		name_rvas, sizeof(DWORD) * exportDir.NumberOfNames)) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read name table\n");
		free(name_rvas);
		return FALSE;
	}

	// Read ordinal table
	WORD* ordinals = (WORD*)malloc(sizeof(WORD) * exportDir.NumberOfNames);
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)((DWORD64)driver_base + exportDir.AddressOfNameOrdinals),
		ordinals, sizeof(WORD) * exportDir.NumberOfNames)) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read ordinal table\n");
		free(name_rvas);
		free(ordinals);
		return FALSE;
	}

	// Read function address table
	DWORD* func_rvas = (DWORD*)malloc(sizeof(DWORD) * exportDir.NumberOfFunctions);
	if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)((DWORD64)driver_base + exportDir.AddressOfFunctions),
		func_rvas, sizeof(DWORD) * exportDir.NumberOfFunctions)) {
		LDRLog(L"PE_GetExportOffsetFromMemory: failed to read function table\n");
		free(name_rvas);
		free(ordinals);
		free(func_rvas);
		return FALSE;
	}

	// Search for the function name
	for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
		char name[256] = { 0 };
		if (!LdrCtx_GetKpTable()->ReadPrimitive((PVOID)((DWORD64)driver_base + name_rvas[i]), name, 255)) {
			continue;
		}
		if (strcmp(name, func_name) == 0) {
			WORD ordinal = ordinals[i];
			*out_offset = func_rvas[ordinal];
			free(name_rvas);
			free(ordinals);
			free(func_rvas);
			return TRUE;
		}
	}

	LDRLog(L"PE_GetExportOffsetFromMemory: export function %S not found\n", func_name);
	free(name_rvas);
	free(ordinals);
	free(func_rvas);
	return FALSE;
} 