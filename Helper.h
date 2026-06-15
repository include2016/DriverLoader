#pragma once
#include <string>
#include <Windows.h>
namespace Helper {
	std::basic_string<TCHAR> GetCurrentDirFilePath(TCHAR* append);

	int StopServiceByName(const char *serviceName);

	bool InstallAndStartDriverService(
		const std::wstring& serviceName,
		const std::wstring& driverPath
	);
	bool ConvertCharToWchar(const char* src, wchar_t* dst, size_t dstChars);
	bool ConvertWcharToChar(const wchar_t* src, char* dst, size_t dstChars);
}

