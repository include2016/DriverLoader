#pragma once
#include <Windows.h>

// hook.save format (simple binary):
//   DWORD  byte_count          -- length of original byte sequence
//   BYTE   original_bytes[]    -- original bytes at hook point (HOOK_POINT_RVA offset in exploit driver)
