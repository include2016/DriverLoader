#include <ntddk.h>
#include "DummyDriverIoctl.h"

// 全局 IOCTL 调用计数器
static volatile LONG64 g_IoctlCallCount = 0;

// 驱动卸载例程
VOID DummyUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(DUMMY_IOCTL_SYM_LINK);
	IoDeleteSymbolicLink(&symLink);

	PDEVICE_OBJECT devObj = DriverObject->DeviceObject;
	if (devObj)
		IoDeleteDevice(devObj);

	KdPrint(("DummyDriverIoctl: Unloaded, total IOCTL calls=%lld\n", g_IoctlCallCount));
}

// IRP_MJ_DEVICE_CONTROL 派遣
NTSTATUS DummyDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	InterlockedIncrement64(&g_IoctlCallCount);

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DUMMY_HELLO:
	{
		const char* msg = "Hello from DummyDriverIoctl!";
		SIZE_T msgLen = strlen(msg) + 1;

		if (outLen >= msgLen)
		{
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, msg, msgLen);
			Irp->IoStatus.Information = (ULONG)msgLen;
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
		}
		KdPrint(("DummyDriverIoctl: IOCTL_DUMMY_HELLO handled, count=%lld\n", g_IoctlCallCount));
		break;
	}
	case IOCTL_DUMMY_GET_COUNT:
	{
		if (outLen >= sizeof(LONG64))
		{
			LONG64 snapshot = g_IoctlCallCount;
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &snapshot, sizeof(LONG64));
			Irp->IoStatus.Information = sizeof(LONG64);
		}
		else
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
		}
		KdPrint(("DummyDriverIoctl: IOCTL_DUMMY_GET_COUNT handled, count=%lld\n", g_IoctlCallCount));
		break;
	}
	case IOCTL_DUMMY_ECHO:
	{
		if (inLen == 0 || outLen == 0)
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}
		ULONG copyLen = (inLen < outLen) ? inLen : outLen;
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, Irp->AssociatedIrp.SystemBuffer, copyLen);
		Irp->IoStatus.Information = copyLen;
		KdPrint(("DummyDriverIoctl: IOCTL_DUMMY_ECHO handled, len=%u, count=%lld\n", copyLen, g_IoctlCallCount));
		break;
	}
	case IOCTL_DUMMY_TERMINATE_PROCESS:
	{
		if (inLen < sizeof(ULONG))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}
		ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES oa;
		CLIENT_ID cid;
		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
		cid.UniqueThread = NULL;
		status = ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &oa, &cid);
		if (NT_SUCCESS(status))
		{
			status = ZwTerminateProcess(hProcess, 0);
			ZwClose(hProcess);
			KdPrint(("DummyDriverIoctl: IOCTL_DUMMY_TERMINATE_PROCESS pid=%u, status=0x%X\n", pid, status));
		}
		else
		{
			KdPrint(("DummyDriverIoctl: IOCTL_DUMMY_TERMINATE_PROCESS pid=%u, ZwOpenProcess failed 0x%X\n", pid, status));
		}
		Irp->IoStatus.Information = 0;
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// 默认 IRP 派遣
NTSTATUS DummyDefaultDispatch(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// DriverEntry
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("DummyDriverIoctl: DriverEntry\n"));

	NTSTATUS status;
	UNICODE_STRING devName = RTL_CONSTANT_STRING(DUMMY_IOCTL_DEVICE_NAME);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(DUMMY_IOCTL_SYM_LINK);
	PDEVICE_OBJECT devObj = NULL;

	status = IoCreateDevice(DriverObject, 0, &devName,
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("DummyDriverIoctl: IoCreateDevice failed 0x%X\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("DummyDriverIoctl: IoCreateSymbolicLink failed 0x%X\n", status));
		IoDeleteDevice(devObj);
		return status;
	}

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DummyDefaultDispatch;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DummyDeviceControl;
	DriverObject->DriverUnload = DummyUnload;

	devObj->Flags |= DO_BUFFERED_IO;
	devObj->Flags &= ~DO_DEVICE_INITIALIZING;

	KdPrint(("DummyDriverIoctl: Initialized, symlink=\\\\.\\DummyDriverIoctl\n"));
	return STATUS_SUCCESS;
}
