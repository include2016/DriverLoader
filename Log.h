#pragma once

#include <Windows.h>
#include <evntprov.h>

// ETW provider GUID for DriverLoader
static const GUID LDR_ProviderGUID =
{ 0x3da12c1, 0x27c2, 0x4d75, { 0x95, 0x3a, 0x2c, 0x4e, 0x66, 0xa3, 0x74, 0x65 } };


extern REGHANDLE g_LDR_ProviderHandle;

void LDRLogEtwInit();
void LDRLog(_In_ PCWSTR Format, ...);
