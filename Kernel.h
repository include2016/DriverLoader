#pragma once
#include <Windows.h>
namespace KRNL {
	NTSTATUS GetDriverBase(
		_In_ PCSTR DriverName,
		_Out_ PVOID* DriverBaseAddress
	);
}
