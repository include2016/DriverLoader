#include "Log.h"
#include "MacroDef.h"
#include "Helper.h"
#include <strsafe.h>

REGHANDLE g_LDR_ProviderHandle = 0;

static HANDLE g_LogFileHandle = INVALID_HANDLE_VALUE;

static void EnsureLogFileOpen() {
	if (g_LogFileHandle != INVALID_HANDLE_VALUE)
		return;

	CHAR log_path[MAX_PATH] = { 0 };
	{
		WCHAR w_log[MAX_PATH] = { 0 };
		Helper::ConvertCharToWchar(LDR_LOG_FILE, w_log, MAX_PATH);
		std::wstring w_full = Helper::GetCurrentDirFilePath((TCHAR*)w_log);
		Helper::ConvertWcharToChar(w_full.c_str(), log_path, MAX_PATH);
	}

	g_LogFileHandle = CreateFileA(log_path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

void LDRLogEtwInit() {
	ULONG status = EventRegister(&LDR_ProviderGUID,
		NULL,
		NULL,
		&g_LDR_ProviderHandle);
	if (status != 0) {
		// ETW register failed, can't log this via ETW - just debug string
		OutputDebugStringW(L"[DriverLoader] EventRegister failed\n");
	}
}

void LDRLog(_In_ PCWSTR Format, ...) {
	WCHAR Buffer[1024];
	va_list args;

	va_start(args, Format);
	_vsnwprintf_s(Buffer, RTL_NUMBER_OF(Buffer) - 1, Format, args);
	va_end(args);

	Buffer[RTL_NUMBER_OF(Buffer) - 1] = L'\0';

	WCHAR Prefixed[1100];
	_snwprintf_s(Prefixed, RTL_NUMBER_OF(Prefixed) - 1, L"[DriverLoader] %s", Buffer);
	Prefixed[RTL_NUMBER_OF(Prefixed) - 1] = L'\0';

	// ETW trace
	EventWriteString(g_LDR_ProviderHandle, 0, 0, Prefixed);

	// DebugView
	OutputDebugStringW(Prefixed);

	// File log
	EnsureLogFileOpen();
	if (g_LogFileHandle != INVALID_HANDLE_VALUE) {
		DWORD written = 0;
		WriteFile(g_LogFileHandle, Prefixed,
			(DWORD)(wcslen(Prefixed) * sizeof(WCHAR)),
			&written, NULL);
	}
}
