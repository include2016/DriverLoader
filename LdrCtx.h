#pragma once
#include <Windows.h>
#include "KernelPower.h"
#include "DummyInterface.hpp"

VOID LdrCtx_SetDevHdl(HANDLE handle);
VOID LdrCtx_SetKrnlBase(PVOID base);

DummyHookServices* LdrCtx_GetInterface();

VOID LdrCtx_SetTrampolineDrvBase(PVOID base);
PVOID LdrCtx_GetTrampolineDrvBase();

VOID LdrCtx_SetExpDrvBase(PVOID base);
PVOID LdrCtx_GetExpDrvBase();

HANDLE LdrCtx_GetDevHdl();
PVOID LdrCtx_GetKrnlBase();

VOID LdrCtx_SetTargetDrvBase(PVOID base);
PVOID LdrCtx_GetTargetDrvBase();
VOID LdrCtx_SetSourceDrvBase(PVOID base);
PVOID LdrCtx_GetSourceDrvBase();

VOID LdrCtx_SetPitRelayAddr(PVOID addr);
PVOID LdrCtx_GetPitRelayAddr();

VOID LdrCtx_SetKpTable(const KP_FUNC_TABLE* pTable);
const KP_FUNC_TABLE* LdrCtx_GetKpTable();
