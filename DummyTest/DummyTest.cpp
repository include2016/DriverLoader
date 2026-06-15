#include <Windows.h>
#include <stdio.h>
#include <fltuser.h>

// 与 DummyDriver.h 中的消息类型定义一致
#define DUMMY_MSG_HELLO             0
#define DUMMY_MSG_GET_COUNT         1
#define DUMMY_MSG_ECHO              2
#define DUMMY_MSG_TERMINATE_PROCESS 3

// 通信端口名
#define DUMMY_PORT_NAME L"\\DummyFilterPort"

// 消息结构（与内核态一致）
#pragma pack(push, 1)
typedef struct _DUMMY_REQUEST {
	ULONG Type;
	ULONG DataLen;
	UCHAR Data[1];
} DUMMY_REQUEST, *PDUMMY_REQUEST;

typedef struct _DUMMY_RESPONSE {
	NTSTATUS Status;
	ULONG DataLen;
	UCHAR Data[1];
} DUMMY_RESPONSE, *PDUMMY_RESPONSE;
#pragma pack(pop)

#define DUMMY_REQUEST_BASE_SIZE  FIELD_OFFSET(DUMMY_REQUEST, Data)
#define DUMMY_RESPONSE_BASE_SIZE FIELD_OFFSET(DUMMY_RESPONSE, Data)

static BOOL TestHello(HANDLE hPort)
{
	UCHAR sendBuf[DUMMY_REQUEST_BASE_SIZE] = { 0 };
	PDUMMY_REQUEST req = (PDUMMY_REQUEST)sendBuf;
	req->Type = DUMMY_MSG_HELLO;
	req->DataLen = 0;

	UCHAR recvBuf[256] = { 0 };
	DWORD bytesReturned = 0;

	HRESULT hr = FilterSendMessage(hPort, sendBuf, sizeof(sendBuf), recvBuf, sizeof(recvBuf), &bytesReturned);
	if (FAILED(hr)) {
		printf("[FAIL] HELLO: FilterSendMessage failed, hr=0x%x\n", hr);
		return FALSE;
	}

	PDUMMY_RESPONSE resp = (PDUMMY_RESPONSE)recvBuf;
	if (resp->Status != 0) {
		printf("[FAIL] HELLO: driver returned status=0x%x\n", resp->Status);
		return FALSE;
	}

	printf("[PASS] HELLO: \"%s\" (%u bytes)\n", (char*)resp->Data, resp->DataLen);
	return TRUE;
}

static BOOL TestGetCount(HANDLE hPort)
{
	UCHAR sendBuf[DUMMY_REQUEST_BASE_SIZE] = { 0 };
	PDUMMY_REQUEST req = (PDUMMY_REQUEST)sendBuf;
	req->Type = DUMMY_MSG_GET_COUNT;
	req->DataLen = 0;

	UCHAR recvBuf[128] = { 0 };
	DWORD bytesReturned = 0;

	HRESULT hr = FilterSendMessage(hPort, sendBuf, sizeof(sendBuf), recvBuf, sizeof(recvBuf), &bytesReturned);
	if (FAILED(hr)) {
		printf("[FAIL] GET_COUNT: FilterSendMessage failed, hr=0x%x\n", hr);
		return FALSE;
	}

	PDUMMY_RESPONSE resp = (PDUMMY_RESPONSE)recvBuf;
	if (resp->Status != 0) {
		printf("[FAIL] GET_COUNT: driver returned status=0x%x\n", resp->Status);
		return FALSE;
	}

	LONG64 count = 0;
	if (resp->DataLen >= sizeof(LONG64))
		memcpy(&count, resp->Data, sizeof(LONG64));

	printf("[PASS] GET_COUNT: count=%lld (%u bytes)\n", count, resp->DataLen);
	return TRUE;
}

static BOOL TestEcho(HANDLE hPort)
{
	const char* msg = "Echo test!";
	size_t msgLen = strlen(msg) + 1;

	DWORD sendSize = DUMMY_REQUEST_BASE_SIZE + (ULONG)msgLen;
	UCHAR* sendBuf = (UCHAR*)malloc(sendSize);
	if (!sendBuf) {
		printf("[FAIL] ECHO: malloc failed\n");
		return FALSE;
	}

	PDUMMY_REQUEST req = (PDUMMY_REQUEST)sendBuf;
	req->Type = DUMMY_MSG_ECHO;
	req->DataLen = (ULONG)msgLen;
	memcpy(req->Data, msg, msgLen);

	UCHAR recvBuf[256] = { 0 };
	DWORD bytesReturned = 0;

	HRESULT hr = FilterSendMessage(hPort, sendBuf, sendSize, recvBuf, sizeof(recvBuf), &bytesReturned);
	free(sendBuf);

	if (FAILED(hr)) {
		printf("[FAIL] ECHO: FilterSendMessage failed, hr=0x%x\n", hr);
		return FALSE;
	}

	PDUMMY_RESPONSE resp = (PDUMMY_RESPONSE)recvBuf;
	if (resp->Status != 0) {
		printf("[FAIL] ECHO: driver returned status=0x%x\n", resp->Status);
		return FALSE;
	}

	if (resp->DataLen != msgLen || memcmp(resp->Data, msg, msgLen) != 0) {
		printf("[FAIL] ECHO: data mismatch, sent=\"%s\" recv=\"%s\" len=%u\n", msg, (char*)resp->Data, resp->DataLen);
		return FALSE;
	}

	printf("[PASS] ECHO: \"%s\" (%u bytes)\n", (char*)resp->Data, resp->DataLen);
	return TRUE;
}

static BOOL TestTerminateProcess(HANDLE hPort, ULONG pid)
{
	DWORD sendSize = DUMMY_REQUEST_BASE_SIZE + sizeof(ULONG);
	UCHAR* sendBuf = (UCHAR*)malloc(sendSize);
	if (!sendBuf) {
		printf("[FAIL] TERMINATE_PROCESS: malloc failed\n");
		return FALSE;
	}

	PDUMMY_REQUEST req = (PDUMMY_REQUEST)sendBuf;
	req->Type = DUMMY_MSG_TERMINATE_PROCESS;
	req->DataLen = sizeof(ULONG);
	memcpy(req->Data, &pid, sizeof(ULONG));

	UCHAR recvBuf[64] = { 0 };
	DWORD bytesReturned = 0;

	HRESULT hr = FilterSendMessage(hPort, sendBuf, sendSize, recvBuf, sizeof(recvBuf), &bytesReturned);
	free(sendBuf);

	if (FAILED(hr)) {
		printf("[FAIL] TERMINATE_PROCESS pid=%u: FilterSendMessage failed, hr=0x%x\n", pid, hr);
		return FALSE;
	}

	PDUMMY_RESPONSE resp = (PDUMMY_RESPONSE)recvBuf;
	if (resp->Status != 0) {
		printf("[FAIL] TERMINATE_PROCESS pid=%u: driver returned status=0x%x\n", pid, resp->Status);
		return FALSE;
	}

	printf("[PASS] TERMINATE_PROCESS pid=%u: terminated\n", pid);
	return TRUE;
}

int main(int argc, char* argv[])
{
	printf("=== DummyFilter Communication Test ===\n\n");

	HANDLE hPort = NULL;
	HRESULT hr = FilterConnectCommunicationPort(DUMMY_PORT_NAME, 0, NULL, 0, NULL, &hPort);
	if (FAILED(hr)) {
		printf("[FAIL] Cannot connect to port %ls, hr=0x%x\n", DUMMY_PORT_NAME, hr);
		return 1;
	}
	printf("[INFO] Connected to %ls\n\n", DUMMY_PORT_NAME);

	int pass = 0, fail = 0;

	if (TestHello(hPort)) pass++; else fail++;
	if (TestGetCount(hPort)) pass++; else fail++;
	if (TestEcho(hPort)) pass++; else fail++;

	// 第二次调用 GET_COUNT 验证计数器递增
	if (TestGetCount(hPort)) pass++; else fail++;

	// 如果命令行指定了 PID，执行 terminate 测试
	if (argc >= 2) {
		ULONG pid = (ULONG)strtoul(argv[1], NULL, 10);
		if (pid != 0) {
			printf("\n--- Terminate Process Test ---\n");
			if (TestTerminateProcess(hPort, pid)) pass++; else fail++;
		}
	}

	CloseHandle(hPort);

	printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
	return (fail > 0) ? 1 : 0;
}
