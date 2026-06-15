#include <fltkernel.h>
#include "DummyDriver.h"

// 全局 IOCTL 调用计数器
static volatile LONG64 g_IoctlCallCount = 0;

// minifilter 全局
static PFLT_FILTER gFilterHandle = NULL;
static PFLT_PORT gServerPort = NULL;

// 前向声明
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS DummyUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS DummyQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS DummyPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_ PVOID *CompletionContext);
NTSTATUS DummyConnectNotify(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie, _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);
VOID DummyDisconnectNotify(_In_opt_ PVOID ConnectionPortCookie);
NTSTATUS DummyMessageNotify(_In_opt_ PVOID PortCookie, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength, _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);

// 操作回调表 — 不拦截任何操作
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_OPERATION_END }
};

// 上下文注册表（无上下文）
CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
	{ FLT_CONTEXT_END }
};

// Filter 注册结构
CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),           // Size
	FLT_REGISTRATION_VERSION,           // Version
	0,                                  // Flags
	NULL,                               // Context Registration
	Callbacks,                          // Operation callbacks
	DummyUnload,                        // FilterUnload
	NULL,                               // InstanceSetup
	DummyQueryTeardown,                 // InstanceQueryTeardown
	NULL,                               // InstanceTeardownStart
	NULL,                               // InstanceTeardownComplete
	NULL,                               // GenerateFileName
	NULL,                               // NormalizeName
	NULL,                               // NormalizeContextCleanup
	NULL,                               // TransactionNotificationCallback
	NULL,                               // NormalizeName
};

// Pre-operation callback — 不拦截，直接放行
FLT_PREOP_CALLBACK_STATUS DummyPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_ PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	*CompletionContext = NULL;
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Query teardown — 允许卸载
NTSTATUS DummyQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	return STATUS_SUCCESS;
}

// Connect notify — 用户态连接通信端口
NTSTATUS DummyConnectNotify(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	*ConnectionPortCookie = ClientPort;
	KdPrint(("DummyFilter: Client connected\n"));
	return STATUS_SUCCESS;
}

// Disconnect notify — 用户态断开通信端口
VOID DummyDisconnectNotify(_In_opt_ PVOID ConnectionPortCookie)
{
	UNREFERENCED_PARAMETER(ConnectionPortCookie);
	KdPrint(("DummyFilter: Client disconnected\n"));
}

// 通信端口消息回调
NTSTATUS DummyMessageNotify(
	_In_ PVOID PortCookie,
	_In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_writes_bytes_to_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_Out_ PULONG ReturnOutputBufferLength)
{
	UNREFERENCED_PARAMETER(PortCookie);

	InterlockedIncrement64(&g_IoctlCallCount);

	if (InputBufferLength < (ULONG)DUMMY_REQUEST_BASE_SIZE || !InputBuffer) {
		*ReturnOutputBufferLength = 0;
		return STATUS_INVALID_PARAMETER;
	}

	PDUMMY_REQUEST req = (PDUMMY_REQUEST)InputBuffer;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG replyLen = 0;
	PDUMMY_RESPONSE resp = (PDUMMY_RESPONSE)OutputBuffer;

	if (!resp || OutputBufferLength < (ULONG)DUMMY_RESPONSE_BASE_SIZE) {
		*ReturnOutputBufferLength = 0;
		return STATUS_BUFFER_TOO_SMALL;
	}

	switch (req->Type)
	{
	case DUMMY_MSG_HELLO:
	{
		const char* msg = "Hello from DummyFilter!";
		SIZE_T msgLen = strlen(msg) + 1;
		ULONG needed = (ULONG)(DUMMY_RESPONSE_BASE_SIZE + msgLen);
		if (OutputBufferLength >= needed) {
			resp->Status = STATUS_SUCCESS;
			resp->DataLen = (ULONG)msgLen;
			RtlCopyMemory(resp->Data, msg, msgLen);
			replyLen = needed;
		} else {
			resp->Status = STATUS_BUFFER_TOO_SMALL;
			resp->DataLen = 0;
			replyLen = DUMMY_RESPONSE_BASE_SIZE;
		}
		KdPrint(("DummyFilter: HELLO handled, count=%lld\n", g_IoctlCallCount));
		break;
	}
	case DUMMY_MSG_GET_COUNT:
	{
		ULONG needed = DUMMY_RESPONSE_BASE_SIZE + sizeof(LONG64);
		if (OutputBufferLength >= needed) {
			LONG64 snapshot = g_IoctlCallCount;
			resp->Status = STATUS_SUCCESS;
			resp->DataLen = sizeof(LONG64);
			RtlCopyMemory(resp->Data, &snapshot, sizeof(LONG64));
			replyLen = needed;
		} else {
			resp->Status = STATUS_BUFFER_TOO_SMALL;
			resp->DataLen = 0;
			replyLen = DUMMY_RESPONSE_BASE_SIZE;
		}
		KdPrint(("DummyFilter: GET_COUNT handled, count=%lld\n", g_IoctlCallCount));
		break;
	}
	case DUMMY_MSG_ECHO:
	{
		ULONG echoDataLen = req->DataLen;
		if (echoDataLen == 0) {
			resp->Status = STATUS_BUFFER_TOO_SMALL;
			resp->DataLen = 0;
			replyLen = DUMMY_RESPONSE_BASE_SIZE;
			break;
		}
		// Validate input has enough data
		if (InputBufferLength < (ULONG)DUMMY_REQUEST_BASE_SIZE + echoDataLen) {
			resp->Status = STATUS_INVALID_PARAMETER;
			resp->DataLen = 0;
			replyLen = DUMMY_RESPONSE_BASE_SIZE;
			break;
		}
		ULONG needed = DUMMY_RESPONSE_BASE_SIZE + echoDataLen;
		if (OutputBufferLength >= needed) {
			resp->Status = STATUS_SUCCESS;
			resp->DataLen = echoDataLen;
			RtlCopyMemory(resp->Data, req->Data, echoDataLen);
			replyLen = needed;
		} else {
			// Copy as much as possible
			ULONG copyLen = (OutputBufferLength > (ULONG)DUMMY_RESPONSE_BASE_SIZE)
				? (OutputBufferLength - (ULONG)DUMMY_RESPONSE_BASE_SIZE) : 0;
			if (copyLen > echoDataLen) copyLen = echoDataLen;
			resp->Status = STATUS_BUFFER_TOO_SMALL;
			resp->DataLen = copyLen;
			if (copyLen > 0)
				RtlCopyMemory(resp->Data, req->Data, copyLen);
			replyLen = DUMMY_RESPONSE_BASE_SIZE + copyLen;
		}
		KdPrint(("DummyFilter: ECHO handled, len=%u, count=%lld\n", echoDataLen, g_IoctlCallCount));
		break;
	}
	case DUMMY_MSG_TERMINATE_PROCESS:
	{
		// Data 前 4 字节为 ULONG PID
		if (req->DataLen < sizeof(ULONG) || InputBufferLength < (ULONG)DUMMY_REQUEST_BASE_SIZE + sizeof(ULONG)) {
			resp->Status = STATUS_BUFFER_TOO_SMALL;
			resp->DataLen = 0;
			replyLen = DUMMY_RESPONSE_BASE_SIZE;
			break;
		}
		ULONG pid = 0;
		RtlCopyMemory(&pid, req->Data, sizeof(ULONG));

		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES oa;
		CLIENT_ID cid;
		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
		cid.UniqueThread = NULL;

		NTSTATUS openStatus = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &oa, &cid);
		if (NT_SUCCESS(openStatus)) {
			NTSTATUS termStatus = ZwTerminateProcess(hProcess, 0);
			ZwClose(hProcess);
			resp->Status = termStatus;
			KdPrint(("DummyFilter: TERMINATE_PROCESS pid=%u, status=0x%X\n", pid, termStatus));
		} else {
			resp->Status = openStatus;
			KdPrint(("DummyFilter: TERMINATE_PROCESS pid=%u, ZwOpenProcess failed 0x%X\n", pid, openStatus));
		}
		resp->DataLen = 0;
		replyLen = DUMMY_RESPONSE_BASE_SIZE;
		break;
	}
	default:
		resp->Status = STATUS_INVALID_DEVICE_REQUEST;
		resp->DataLen = 0;
		replyLen = DUMMY_RESPONSE_BASE_SIZE;
		break;
	}

	*ReturnOutputBufferLength = replyLen;
	return status;
}

// Unload
NTSTATUS DummyUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

	if (gServerPort) {
		FltCloseCommunicationPort(gServerPort);
		gServerPort = NULL;
	}
	if (gFilterHandle) {
		FltUnregisterFilter(gFilterHandle);
		gFilterHandle = NULL;
	}

	KdPrint(("DummyFilter: Unloaded, total calls=%lld\n", g_IoctlCallCount));
	return STATUS_SUCCESS;
}

// DriverEntry
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("DummyFilter: DriverEntry\n"));

	NTSTATUS status;

	// 注册 minifilter
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("DummyFilter: FltRegisterFilter failed 0x%X\n", status));
		return status;
	}

	// 启动过滤
	status = FltStartFiltering(gFilterHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("DummyFilter: FltStartFiltering failed 0x%X\n", status));
		FltUnregisterFilter(gFilterHandle);
		gFilterHandle = NULL;
		return status;
	}

	// 创建通信端口
	UNICODE_STRING portName = RTL_CONSTANT_STRING(DUMMY_PORT_NAME);
	PSECURITY_DESCRIPTOR sd = NULL;
	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	if (!NT_SUCCESS(status)) {
		KdPrint(("DummyFilter: FltBuildDefaultSecurityDescriptor failed 0x%X\n", status));
		FltUnregisterFilter(gFilterHandle);
		gFilterHandle = NULL;
		return status;
	}

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

	status = FltCreateCommunicationPort(gFilterHandle, &gServerPort, &oa, NULL, DummyConnectNotify, DummyDisconnectNotify, DummyMessageNotify, 1);
	FltFreeSecurityDescriptor(sd);

	if (!NT_SUCCESS(status)) {
		KdPrint(("DummyFilter: FltCreateCommunicationPort failed 0x%X\n", status));
		FltUnregisterFilter(gFilterHandle);
		gFilterHandle = NULL;
		return status;
	}

	KdPrint(("DummyFilter: Initialized, port=\\DummyFilterPort\n"));
	return STATUS_SUCCESS;
}
