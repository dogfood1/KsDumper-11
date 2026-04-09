# KsDumper-11 增强版

[English](README.md)

基于 [KsDumper-11](https://github.com/mastercodeon314/KsDumper-11) 的增强版，新增**写进程内存**、**读内核内存**和 **DSE 开关控制**功能。

## 新增功能

### 写进程内存 (`IO_WRITE_MEMORY`)

通过 MDL 映射向任意进程的虚拟内存写入数据，支持写保护页面（通过 `MmProtectMdlSystemAddress` 处理）。

### 读内核内存 (`IO_READ_KERNEL`)

从用户态直接读取内核空间地址（如 CI.dll、ntoskrnl 数据段），使用 `RtlCopyMemory` + `MmIsAddressValid` 安全检查。

### DSE 开关控制 (`IO_DSE_*`)

运行时启用/禁用 Windows 驱动签名强制（DSE），通过修改 CI.dll 中的 `g_CiOptions` 实现。使用 [KDU](https://github.com/hfiref0x/KDU) 的方法，通过反汇编 `CiInitialize` 导出函数精确定位 `g_CiOptions`。

## IOCTL 接口

设备名: `\\.\KsDumper`

| IOCTL | 代码 | 说明 |
|-------|------|------|
| `IO_GET_PROCESS_LIST` | `0x1724` | 枚举进程 |
| `IO_COPY_MEMORY` | `0x1725` | 读进程内存 |
| `IO_UNLOAD_DRIVER` | `0x1726` | 卸载驱动 |
| `IO_WRITE_MEMORY` | `0x1727` | 写进程内存 |
| `IO_READ_KERNEL` | `0x1728` | 读内核内存 |
| `IO_DSE_SET_ADDR` | `0x1730` | 设置 g_CiOptions 地址 |
| `IO_DSE_DISABLE` | `0x1731` | 关闭 DSE (g_CiOptions = 0) |
| `IO_DSE_ENABLE` | `0x1732` | 恢复 DSE |
| `IO_DSE_QUERY` | `0x1733` | 查询 DSE 状态 |

## 数据结构

### KERNEL_COPY_MEMORY_OPERATION（读写进程内存）

```c
typedef struct {
    INT32 targetProcessId;    // 目标进程 ID
    PVOID targetAddress;      // 目标进程中的地址
    PVOID bufferAddress;      // 用户态缓冲区
    INT32 bufferSize;         // 大小
} KERNEL_COPY_MEMORY_OPERATION;
```

### KERNEL_READ_KERNEL_OPERATION（读内核内存）

```c
typedef struct {
    ULONG64 kernelAddress;    // 内核空间源地址
    PVOID   bufferAddress;    // 用户态目标缓冲区
    INT32   bufferSize;       // 大小（最大 1MB）
} KERNEL_READ_KERNEL_OPERATION;
```

### KERNEL_DSE_OPERATION（DSE 控制）

```c
#define DSE_MAX_ADDRS 8

typedef struct {
    ULONG   count;                      // 地址数量
    ULONG64 addresses[DSE_MAX_ADDRS];   // 内核地址
    ULONG   originals[DSE_MAX_ADDRS];   // 原始值
} KERNEL_DSE_OPERATION;
```

## DSE 控制工具

```
dse_client.exe init             定位 g_CiOptions（通过反汇编 CiInitialize）
dse_client.exe query            查询 DSE 状态
dse_client.exe off              关闭 DSE
dse_client.exe on               恢复 DSE
dse_client.exe load <file.sys>  一键加载未签名驱动（自动 Init+Off+Load+On）
```

### g_CiOptions 定位原理

1. `NtQuerySystemInformation(SystemModuleInformation)` 获取 CI.dll 内核基址
2. `LoadLibraryEx` 在用户态映射 CI.dll
3. `GetProcAddress` 获取 `CiInitialize` 导出函数地址
4. 反汇编 `CiInitialize`，找到 `call CipInitialize`（`E8` 操作码前有 3 个以上参数设置指令）
5. 反汇编 `CipInitialize`，找到第一个 `mov [rip+disp32], r32`（操作码 `89 xx`，`ModRM & 0xC7 == 0x05`）
6. 计算内核地址: `CI.dll 基址 + (文件偏移 - 映射基址)`

### 使用示例

```bat
dse_client.exe load C:\path\to\unsigned.sys
```

输出:
```
[1] Init
[*] CI.dll kernel base: 0xFFFFF80518E40000
[*] CiInitialize at: 0x00007FFF8D68E430
[*] Found call CipInitialize at CiInit+0x2F
[+] g_CiOptions (kern) = 0xFFFFF80518E7D004
[+] Set OK, 1 addr(s), value=0x6
[2] Off
[+] DSE DISABLED
[3] Load C:\path\to\unsigned.sys
[+] Loaded: C:\path\to\unsigned.sys
[4] On
[+] DSE RESTORED
```

## 编译

### 驱动

用 VS2019 打开 `KsDumper11.sln`，编译 `KsDumperDriver` 项目（Release x64）。

### DSE 客户端

```bat
cl /Fe:dse_client.exe dse_client.c advapi32.lib
```

## 修改文件

```
KsDumperDriver/
  Driver.c              + WriteVirtualMemory（MDL 写内存）
                        + IO_WRITE_MEMORY 处理
                        + IO_READ_KERNEL 处理
                        + IO_DSE_SET_ADDR/DISABLE/ENABLE/QUERY 处理
                        + DseWriteAll（DISPATCH_LEVEL 下切换 CR0.WP）

  UserModeBridge.h      + IO_WRITE_MEMORY, IO_READ_KERNEL 定义
                        + IO_DSE_* 定义
                        + KERNEL_READ_KERNEL_OPERATION 结构体
                        + KERNEL_DSE_OPERATION 结构体

dse_client.c            新增 - DSE 控制工具
```

## 安全说明

- DSE 修改仅涉及一个 DWORD (`g_CiOptions`)
- 每次内核内存访问前使用 `MmIsAddressValid` 检查有效性
- 在 DISPATCH_LEVEL 切换 CR0.WP，防止线程抢占
- 执行 `dse_client.exe on` 或 `IO_DSE_ENABLE` 时自动恢复原始值
- 写内存使用 MDL 映射 + `__try/__except` 异常保护

## 致谢

- 原版 KsDumper: [EquiFox](https://github.com/EquiFox/KsDumper)
- Windows 11 移植: [mastercodeon314](https://github.com/mastercodeon314/KsDumper-11)
- DSE 定位方法参考: [KDU](https://github.com/hfiref0x/KDU) by hfiref0x
