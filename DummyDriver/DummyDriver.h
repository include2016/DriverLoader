#pragma once

#include <ntddk.h>
#include <fltkernel.h>

// minifilter 通信端口名
#define DUMMY_PORT_NAME L"\\DummyFilterPort"

// 消息类型
#define DUMMY_MSG_HELLO             0
#define DUMMY_MSG_GET_COUNT         1
#define DUMMY_MSG_ECHO              2
#define DUMMY_MSG_TERMINATE_PROCESS 3

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

// 内核态-用户态通信消息结构
#pragma pack(push, 1)
typedef struct _DUMMY_REQUEST {
	ULONG Type;       // DUMMY_MSG_HELLO / GET_COUNT / ECHO
	ULONG DataLen;    // ECHO 时输入数据长度
	UCHAR Data[1];    // 变长数据起始（仅 ECHO 使用）
} DUMMY_REQUEST, *PDUMMY_REQUEST;

typedef struct _DUMMY_RESPONSE {
	NTSTATUS Status;
	ULONG DataLen;
	UCHAR Data[1];    // 变长数据起始
} DUMMY_RESPONSE, *PDUMMY_RESPONSE;
#pragma pack(pop)

// 辅助宏：计算请求/响应结构大小（不含变长 Data 本身）
#define DUMMY_REQUEST_BASE_SIZE  FIELD_OFFSET(DUMMY_REQUEST, Data)
#define DUMMY_RESPONSE_BASE_SIZE FIELD_OFFSET(DUMMY_RESPONSE, Data)

// minifilter altitude（370000 = Activity Monitor 层）
#define DUMMY_ALTITUDE L"370000"
