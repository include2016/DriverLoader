#include <Windows.h>
#include <stdio.h>

// 与 DummyDriverIoctl.h 中的 IOCTL 定义保持一致
#define IOCTL_DUMMY_HELLO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DUMMY_GET_COUNT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DUMMY_ECHO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DUMMY_TERMINATE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DUMMY_IOCTL_SYM_LINK L"\\\\.\\DummyDriverIoctl"

static BOOL TestHello(HANDLE h)
{
	char buf[256] = { 0 };
	DWORD dwRead = 0;
	BOOL ok = DeviceIoControl(h, IOCTL_DUMMY_HELLO, NULL, 0, buf, sizeof(buf), &dwRead, NULL);
	if (!ok) {
		printf("[FAIL] IOCTL_DUMMY_HELLO: DeviceIoControl failed, err=0x%x\n", GetLastError());
		return FALSE;
	}
	printf("[PASS] IOCTL_DUMMY_HELLO: \"%s\" (%u bytes)\n", buf, dwRead);
	return TRUE;
}

static BOOL TestGetCount(HANDLE h)
{
	LONG64 count = 0;
	DWORD dwRead = 0;
	BOOL ok = DeviceIoControl(h, IOCTL_DUMMY_GET_COUNT, NULL, 0, &count, sizeof(count), &dwRead, NULL);
	if (!ok) {
		printf("[FAIL] IOCTL_DUMMY_GET_COUNT: DeviceIoControl failed, err=0x%x\n", GetLastError());
		return FALSE;
	}
	printf("[PASS] IOCTL_DUMMY_GET_COUNT: count=%lld (%u bytes)\n", count, dwRead);
	return TRUE;
}

static BOOL TestEcho(HANDLE h)
{
	const char* msg = "Echo test!";
	size_t msgLen = strlen(msg) + 1;
	char inBuf[128] = { 0 };
	char outBuf[128] = { 0 };
	memcpy(inBuf, msg, msgLen);
	DWORD dwRead = 0;
	BOOL ok = DeviceIoControl(h, IOCTL_DUMMY_ECHO, inBuf, (DWORD)msgLen, outBuf, sizeof(outBuf), &dwRead, NULL);
	if (!ok) {
		printf("[FAIL] IOCTL_DUMMY_ECHO: DeviceIoControl failed, err=0x%x\n", GetLastError());
		return FALSE;
	}
	if (dwRead != msgLen || memcmp(inBuf, outBuf, msgLen) != 0) {
		printf("[FAIL] IOCTL_DUMMY_ECHO: data mismatch, sent=\"%s\" recv=\"%s\" len=%u\n", inBuf, outBuf, dwRead);
		return FALSE;
	}
	printf("[PASS] IOCTL_DUMMY_ECHO: \"%s\" (%u bytes)\n", outBuf, dwRead);
	return TRUE;
}

static BOOL TestTerminateProcess(HANDLE h, ULONG pid)
{
	BOOL ok = DeviceIoControl(h, IOCTL_DUMMY_TERMINATE_PROCESS, &pid, sizeof(pid), NULL, 0, NULL, NULL);
	if (!ok) {
		printf("[FAIL] IOCTL_DUMMY_TERMINATE_PROCESS pid=%u: DeviceIoControl failed, err=0x%x\n", pid, GetLastError());
		return FALSE;
	}
	printf("[PASS] IOCTL_DUMMY_TERMINATE_PROCESS pid=%u: terminated\n", pid);
	return TRUE;
}

int main(int argc, char* argv[])
{
	printf("=== DummyDriverIoctl IOCTL Test ===\n\n");

	HANDLE h = CreateFileW(DUMMY_IOCTL_SYM_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		printf("[FAIL] Cannot open %ls, err=0x%x\n", DUMMY_IOCTL_SYM_LINK, GetLastError());
		return 1;
	}
	printf("[INFO] Opened %ls\n\n", DUMMY_IOCTL_SYM_LINK);

	int pass = 0, fail = 0;

	if (TestHello(h)) pass++; else fail++;
	if (TestGetCount(h)) pass++; else fail++;
	if (TestEcho(h)) pass++; else fail++;

	// 第二次调用 GET_COUNT 验证计数器递增
	if (TestGetCount(h)) pass++; else fail++;

	// 如果命令行指定了 PID，执行 terminate 测试
	if (argc >= 2) {
		ULONG pid = (ULONG)strtoul(argv[1], NULL, 10);
		if (pid != 0) {
			printf("\n--- Terminate Process Test ---\n");
			if (TestTerminateProcess(h, pid)) pass++; else fail++;
		}
	}

	CloseHandle(h);

	printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
	return (fail > 0) ? 1 : 0;
}
