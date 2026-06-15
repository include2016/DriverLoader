#pragma once

// Exploit driver symlink is now managed by KernelPower DLL internally


#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)

#define STATUS_SUCCESS 0

// Trampoline stage layout constants
#define TO_DESK_TRAMPOLINE_CODE_OFFSET 0x27A8
#define TO_DESK_TRAMPOLINE_CODE_STAGE_2_OFFSET 0x29C4
#define OFFSET_FOR_ORIGINAL_ASM_CODE_SAVE 0x330
#define TO_DESK_SHELLCODE_ADDR 0x2AA0
#define TO_DESK_TRAMPOLINE_PIT_OFFSET 0x2B40

// Exploit driver hook point RVA and driver name are read from hookconfig.ini at runtime

// Trampoline driver (dedicated, same as KrnlModeHookHlp)
#define TRAMPOLINE_DRV_NAME "evbda.sys"

#define HOOK_CONFIG_FILE "hookconfig.ini"
#define HOOKSAVE_FILE "hook.save"

#define DUMP_FILE_SUFFIX ".text.dump"

#define LDR_LOG_FILE "DriverLoader.log"

// ff25 hook constants
#define ff25jmpsize 6
#define ff25_opcode_size 2

// Trampoline stage offsets (within each trampoline export function)
#define stage_0_xoreaxeaxret_size 0x3
#define stage_0_placeholder_size 0x8
#define TRAMPOLINE_PIT_OFFSET_STAGE_2_FUNC 0x110

// ntoskrnl DbgPrompt (used as PIT relay when distance > 4GB)
#define NTKRNL_NAME "ntoskrnl.exe"
#define DBG_EXPORT_FUNC "DbgPrompt"

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
