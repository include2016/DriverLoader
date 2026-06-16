#pragma once
#include <Windows.h>
#include <strsafe.h>
#include <string>
#include <vector>
#include "KernelPower.h"
#include "HookServices.h"

// Forward declarations
struct HookRow;
const KP_FUNC_TABLE* LdrCtx_GetKpTable();

class DummyHookServices final : public HookServicesBase {
public:

	  BOOLEAN ReadPrimitive(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size) override {
		  const KP_FUNC_TABLE* kp = LdrCtx_GetKpTable();
		  if (kp && kp->ReadPrimitive)
			  return kp->ReadPrimitive(target_addr, buffer, size);
		  return FALSE;
	  }
	  BOOLEAN WritePrimitive(_In_ LPVOID target_addr, _In_ LPVOID buffer, _In_ size_t size) override {
		  const KP_FUNC_TABLE* kp = LdrCtx_GetKpTable();
		  if (kp && kp->WritePrimitive)
			  return kp->WritePrimitive(target_addr, buffer, size);
		  return FALSE;
	  }
	void LogCore(const wchar_t* fmt, ...) override {
		wchar_t buffer[1024];
		va_list ap;
		va_start(ap, fmt);
		_vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, fmt, ap);
		va_end(ap);
		wprintf_s(L"[HookCore]   %s", buffer);
	}
};
