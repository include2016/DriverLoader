# DriverLoader / Windows DSE bypass

利用漏洞驱动的内核读/写/执行原语，将 shellcode 注入目标内核驱动并劫持其执行流的框架。

## 架构

```
DriverLoader.exe              主程序，读取配置、加载 KernelPower DLL、执行 hook 流程
    |
    +-- KernelPower.dll       可插拔 DLL，封装漏洞驱动的读写/触发原语（需自行实现）
    |
    +-- hookconfig.ini        运行时配置（目标驱动名、hook 点 RVA）
    |
    +-- <未签名驱动>.sys        待加载的未签名内核驱动（由 hookconfig.ini 指定）
    |
    +-- todeskaudio.sys       用于提供构造trampoline code空间的驱动
    |
    +-- hook.save             保存原始代码，用于恢复
```

DriverLoader 通过 `LoadLibrary("KernelPower.dll")` 加载内核原语 DLL，调用其导出函数获取读写/触发能力，然后在已签名的 trampoline 驱动中构建跳板，将未签名驱动的代码注入其中，绕过 DSE（驱动签名强制）加载运行。

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
SourceDriver=your_driver.sys    ; 待加载的未签名驱动文件名（需放在 DriverLoader 同目录）
ExpDriverName=YourExploit.sys   ; 漏洞驱动文件名（需放在 DriverLoader 同目录）
HookPointRVA=ABCDE              ; trampoline 驱动中的 hook 点 RVA（十六进制）
Altitude=120000					; minifilter驱动的altitude值
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
1. 读取 hookconfig.ini 获取未签名驱动名、漏洞驱动名和 hook RVA
2. 启动漏洞驱动，evbda.sys和 trampoline 驱动（通过 SCM）
3. LoadLibrary("KernelPower.dll")
4. KpInitialize() → 打开漏洞驱动设备
5. KpGetTable()    → 获取读/写/触发函数表
6. 将未签名驱动的代码写入 evbda.sys 驱动的 .text 段
7. 在 hook 点写入 trampoline 跳转，劫持执行流到未签名驱动代码
8. TriggerExecute() → 触发漏洞驱动执行 shellcode
9. KpCleanup() → 释放资源
```
