#include "LdrCtx.h"

static DummyHookServices dummy_hook_services;
static HANDLE device_handle;
static PVOID ntoskrnl_base;
static PVOID trampoline_drv_base;
static PVOID exp_drv_base;
static PVOID target_drv_base;
static PVOID source_drv_base;
static PVOID pit_relay_addr;
static const KP_FUNC_TABLE* kp_table = NULL;

DummyHookServices* LdrCtx_GetInterface() {
	return &dummy_hook_services;
}
VOID LdrCtx_SetDevHdl(HANDLE handle) {
	device_handle = handle;
}

VOID LdrCtx_SetKrnlBase(PVOID base) {
	ntoskrnl_base = base;
}

VOID LdrCtx_SetTrampolineDrvBase(PVOID base) {
	trampoline_drv_base = base;
}
PVOID LdrCtx_GetTrampolineDrvBase() {
	return trampoline_drv_base;
}

VOID LdrCtx_SetExpDrvBase(PVOID base) {
	exp_drv_base = base;
}
PVOID LdrCtx_GetExpDrvBase() {
	return exp_drv_base;
}

HANDLE LdrCtx_GetDevHdl() {
	return device_handle;
}

PVOID LdrCtx_GetKrnlBase() {
	return ntoskrnl_base;
}

VOID LdrCtx_SetTargetDrvBase(PVOID base) {
	target_drv_base = base;
}
PVOID LdrCtx_GetTargetDrvBase() {
	return target_drv_base;
}
VOID LdrCtx_SetSourceDrvBase(PVOID base) {
	source_drv_base = base;
}
PVOID LdrCtx_GetSourceDrvBase() {
	return source_drv_base;
}

VOID LdrCtx_SetPitRelayAddr(PVOID addr) {
	pit_relay_addr = addr;
}
PVOID LdrCtx_GetPitRelayAddr() {
	return pit_relay_addr;
}

VOID LdrCtx_SetKpTable(const KP_FUNC_TABLE* pTable) {
	kp_table = pTable;
}
const KP_FUNC_TABLE* LdrCtx_GetKpTable() {
	return kp_table;
}
