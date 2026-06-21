# 更新 2026-06-21

现已支持对[UsermodeHookHelper](https://github.com/include2016/UserModeHookHelper/releases/tag/v1.1.2)主驱动的加载



https://github.com/user-attachments/assets/5fdbe96c-b28e-421b-a70f-766f9cd3bf4f



# DriverLoader / Windows DSE bypass

利用漏洞驱动的内核读/写/执行原语，将 shellcode 注入目标内核驱动并劫持其执行流的框架。

## 架构

```
DriverLoader.exe                主程序，读取配置、加载 KernelPower DLL、执行 hook 流程
    |                           
    +-- KernelPower.dll         可插拔 DLL，封装漏洞驱动的读写/触发原语（需自行实现）
    |                           
    +-- hookconfig.ini          运行时配置（目标驱动名、hook 点 RVA）
    |
    +-- <未签名驱动>.sys        待加载的未签名内核驱动（由 hookconfig.ini 指定）
    |
    +-- <签名驱动>.sys          已签名驱动，提供代码空间与 trampoline 跳板（由 hookconfig.ini 指定，需放在 DriverLoader 同目录）
    |
    +-- hook.save               保存原始代码，用于恢复
```

DriverLoader 通过 `LoadLibrary("KernelPower.dll")` 加载内核原语 DLL，调用其导出函数获取读写/触发能力，然后在由配置指定的已签名驱动中构建跳板，将未签名驱动的代码注入其中，绕过 DSE（驱动签名强制）加载运行。

## 项目结构

| 项目 | 类型 | 说明 |
|------|------|------|
| **DriverLoader** | EXE | 主程序 |
| **KernelPowerExample** | DLL | KernelPower 模板项目，复制后填写 TODO 即可适配自己的漏洞驱动 |
| **DummyDriver** | WDM minifilter 驱动 | 通信测试用的示例内核驱动 |
| **DummyTest** | EXE | DummyDriver 的用户态通信测试程序 |

## KernelPower DLL 接口规范

KernelPower 是可插拔的内核原语 DLL，每个漏洞驱动对应一个实现。所有实现必须输出同名 `KernelPower.dll`，导出以下三个符号：

```c
BOOL  KpInitialize(void);                // 打开驱动设备，初始化内部状态
const KP_FUNC_TABLE* KpGetTable(void);   // 获取函数指针表
VOID  KpCleanup(void);                    // 释放资源
```

函数表包含三个回调：

```c
typedef struct _KP_FUNC_TABLE {
    BOOLEAN (*ReadPrimitive)(LPVOID target_addr, LPVOID buffer, size_t size);
    BOOLEAN (*WritePrimitive)(LPVOID target_addr, LPVOID buffer, size_t size);
    BOOLEAN (*TriggerExecute)(void);
} KP_FUNC_TABLE;
```

### 实现自己的 KernelPower

1. 复制 `KernelPowerExample/` 目录
2. 修改 `KP_DEVICE_SYMLINK` 和 `KP_IOCTL_CODE` 为你的驱动参数
3. 实现 `KpReadPrimitive`、`KpWritePrimitive`、`KpTriggerExecute` 三个回调
4. 构建输出为 `KernelPower.dll`

详细说明见 `KernelPowerExample/KernelPower.cpp` 头部注释。

## 配置

运行时通过 `hookconfig.ini` 配置：

```ini
[Hook]
SourceDriver=your_driver.sys    			; 待加载的未签名驱动文件名（需放在 DriverLoader 同目录）
ExpDriverName=YourExploit.sys   			; 漏洞驱动文件名（需放在 DriverLoader 同目录）
HookPointRVA=ABCDE              			; 漏洞驱动中的 hook 点 RVA（十六进制）
Altitude=120000                 			; minifilter 驱动的 altitude 值
TrampolineDriver=signed_trampoline.sys      ; 已签名驱动文件名（需放在 DriverLoader 同目录），提供代码空间与 trampoline 跳板
Stage1Offset=0                  			; stage_1 代码相对签名驱动 BaseOfCode 的偏移（十六进制）
Stage2Offset=1000               			; stage_2 代码相对签名驱动 BaseOfCode 的偏移（十六进制）
```


## 构建

- Visual Studio 2017+ (v141 工具集)
- Windows SDK 10.0.16299+
- x64 Debug / Release

```bash
# 构建
msbuild DriverLoader.sln /p:Configuration=Release /p:Platform=x64
```

构建产物输出到 `x64/Release/`（或 `x64/Debug/`）。运行时需要将 `KernelPower.dll` 放到 DriverLoader.exe 同目录。

## 运行流程

```
1. 读取 hookconfig.ini 获取未签名驱动名、漏洞驱动名、hook RVA、trampoline 驱动名、stage 偏移等配置
2. 启动漏洞驱动和 trampoline 驱动（通过 SCM）
3. LoadLibrary("KernelPower.dll")
4. KpInitialize()   → 打开漏洞驱动设备
5. KpGetTable()     → 获取读/写/触发函数表
6. 将未签名驱动的代码写入 trampoline 驱动的 .text 段
7. 在 trampoline 驱动的 stage_1/stage_2 空间中构建 trampoline 跳板
8. 在 hook 点写入 trampoline 跳转，劫持执行流到未签名驱动代码
9. TriggerExecute() → 触发漏洞驱动执行 shellcode
9. KpCleanup()      → 释放资源
```

## 效果

加载普通驱动:

https://github.com/user-attachments/assets/a62d1d92-02aa-400f-9943-eacb9d22e8d2


加载minifilter驱动:

https://github.com/user-attachments/assets/69a4ffa5-4e6b-4bd7-9783-872551234ad7


