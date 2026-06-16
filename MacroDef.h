#pragma once

// Exploit driver symlink is now managed by KernelPower DLL internally

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)

#define STATUS_SUCCESS 0

// Trampoline stage layout constants
#define OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE 0x330
#define TRAMPOLINE_PIT_OFFSET_STAGE_2_FUNC 0x110

// Exploit driver hook point RVA and driver name are read from hookconfig.ini at runtime

#define HOOK_CONFIG_FILE "hookconfig.ini"
#define HOOKSAVE_FILE "hook.save"

#define DUMP_FILE_SUFFIX ".text.dump"

#define LDR_LOG_FILE "DriverLoader.log"

// ff25 hook constants
#define ff25jmpsize 6
#define ff25_opcode_size 2

#define stage_0_xoreaxeaxret_size 0x3
#define stage_0_placeholder_size 0x8

// PIT relay offset within evbda.sys (BaseOfCode + this offset), used when distance > 4GB
#define NTKRNL_NAME "ntoskrnl.exe"
#define EVBDA_PIT_RELAY_OFFSET 0x11B000

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
