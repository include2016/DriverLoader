#include "KernelPower.h"

// ==========================================================================
// KernelPower Example -- Template Implementation
// ==========================================================================
//
// 这是一个 KernelPower DLL 的模板项目。复制此项目并填写 TODO 部分，
// 即可为你的漏洞驱动实现自己的 KernelPower DLL。
//
// 【必须实现的部分】
// ──────────────────────────────────────────────────────────────────────────
//
// 1. 驱动常量（文件顶部）
//    - KP_DEVICE_SYMLINK: 驱动的设备符号链接名，如 L"\\\\.\\Hydra"
//    - KP_IOCTL_CODE:     驱动使用的 IOCTL 控制码，如 0x830020C0
//      如果你的驱动使用多个 IOCTL，可以定义多个常量。
//
// 2. KpInitialize（导出函数）
//    - 打开驱动设备句柄（CreateFileW）
//    - 初始化内部状态，填充函数表
//    - 返回 TRUE 表示成功，DriverLoader 才会继续调用
//
// 3. KpReadPrimitive（静态回调）
//    - 从内核虚拟地址 target_addr 读取 size 字节到 buffer
//    - 典型实现：通过 IOCTL 让驱动映射目标地址到用户空间，再 memcpy
//    - 注意：读取可能跨越页边界，需分块处理
//    - 返回 TRUE 成功 / FALSE 失败
//
// 4. KpWritePrimitive（静态回调）
//    - 将 buffer 中的 size 字节写入内核虚拟地址 target_addr
//    - 典型实现：通过 IOCTL 映射目标地址到用户空间，再 memcpy 写入
//    - 注意：写入也可能跨页，需分块处理；写完后应取消映射
//    - 返回 TRUE 成功 / FALSE 失败
//
// 5. KpTriggerExecute（静态回调）
//    - 触发漏洞驱动执行已写入的 shellcode
//    - 典型实现：发送一个特定 IOCTL，使驱动走到 hook 路径并执行
//    - 调用此函数前，DriverLoader 已通过 WritePrimitive 把 shellcode
//      写入了内核中的目标位置
//    - 返回 TRUE 成功 / FALSE 失败
//
// 【可选实现】
// ──────────────────────────────────────────────────────────────────────────
//
// - KpCleanup: 释放资源（关闭句柄、清空函数表）。当前模板已提供基本
//   实现，一般无需修改。
//
// 【输出 DLL 名称】
// ──────────────────────────────────────────────────────────────────────────
//
// 所有 KernelPower 实现必须输出同名 DLL: KernelPower.dll
// （vcxproj 中已设置 <TargetName>KernelPower</TargetName>）
// DriverLoader 通过 LoadLibrary("KernelPower.dll") 加载，不关心具体
// 哪个实现，只要导出符号 KpInitialize / KpGetTable / KpCleanup 即可。
//
// 【实现参考】
// ──────────────────────────────────────────────────────────────────────────
//
// KernelPower/ 子模块（submodule）包含一个基于 Hydra 驱动的完整实现，
// 可作为参考。其核心流程：
//   Read/Write:  IOCTL(allocate MDL) → 映射到用户空间 → memcpy → IOCTL(free MDL)
//   Trigger:     发送触发 IOCTL 使驱动执行 hook 路径
//
// ==========================================================================

// ---- TODO: 修改为你的驱动设备符号链接 ----
static const WCHAR* KP_DEVICE_SYMLINK = L"\\\\.\\YourDeviceName";
// ---- TODO: 修改为你的驱动 IOCTL 控制码 ----
static const DWORD   KP_IOCTL_CODE    = 0x00000000;
// ------------------------------------------------

static HANDLE g_hDevice = INVALID_HANDLE_VALUE;
static KP_FUNC_TABLE g_table = { 0 };

// ---- TODO: 实现内核内存读取 ----
// 从内核 VA target_addr 读取 size 字节到 buffer，成功返回 TRUE
static BOOLEAN KpReadPrimitive(_In_ LPVOID target_addr, _Out_ LPVOID buffer, _In_ size_t size) {
	// TODO: 通过 IOCTL 让驱动映射内核地址到用户空间，再 memcpy
	(void)target_addr; (void)buffer; (void)size;
	return FALSE;
}

// ---- TODO: 实现内核内存写入 ----
// 将 buffer 中的 size 字节写入内核 VA target_addr，成功返回 TRUE
static BOOLEAN KpWritePrimitive(_In_ LPVOID target_addr, _In_ LPVOID buffer, _In_ size_t size) {
	// TODO: 通过 IOCTL 让驱动映射内核地址到用户空间，再 memcpy 写入
	(void)target_addr; (void)buffer; (void)size;
	return FALSE;
}

// ---- TODO: 实现触发执行 ----
// 发送触发 IOCTL 使漏洞驱动执行已写入的 shellcode，成功返回 TRUE
static BOOLEAN KpTriggerExecute(void) {
	// TODO: 发送触发 IOCTL 到你的驱动
	return FALSE;
}

// ---- 导出函数（一般无需修改） ----

KP_API BOOL KpInitialize(void) {
	// TODO: 打开你的驱动设备句柄
	g_hDevice = CreateFileW(
		KP_DEVICE_SYMLINK,
		GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM, 0
	);
	if (g_hDevice == INVALID_HANDLE_VALUE)
		return FALSE;

	g_table.ReadPrimitive  = KpReadPrimitive;
	g_table.WritePrimitive = KpWritePrimitive;
	g_table.TriggerExecute = KpTriggerExecute;
	return TRUE;
}

KP_API const KP_FUNC_TABLE* KpGetTable(void) {
	return &g_table;
}

KP_API VOID KpCleanup(void) {
	if (g_hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(g_hDevice);
		g_hDevice = INVALID_HANDLE_VALUE;
	}
	g_table.ReadPrimitive  = NULL;
	g_table.WritePrimitive = NULL;
	g_table.TriggerExecute = NULL;
}
