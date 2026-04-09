# KsDumper-11 Enhanced

Fork of [KsDumper-11](https://github.com/mastercodeon314/KsDumper-11) with added **Write Memory**, **Kernel Memory Read**, and **DSE Control** capabilities.

基于 [KsDumper-11](https://github.com/mastercodeon314/KsDumper-11) 的增强版，新增**写进程内存**、**读内核内存**和 **DSE 开关控制**功能。

---

## New Features / 新增功能

### Write Process Memory / 写进程内存 (`IO_WRITE_MEMORY`)

Write arbitrary data to any process's virtual memory using MDL-based mapping. Handles write-protected pages via `MmProtectMdlSystemAddress`.

通过 MDL 映射向任意进程的虚拟内存写入数据，支持写保护页面（通过 `MmProtectMdlSystemAddress` 处理）。

### Read Kernel Memory / 读内核内存 (`IO_READ_KERNEL`)

Directly read kernel-space addresses (e.g., CI.dll, ntoskrnl data sections) from user-mode. Uses `RtlCopyMemory` with `MmIsAddressValid` safety checks.

从用户态直接读取内核空间地址（如 CI.dll、ntoskrnl 数据段），使用 `RtlCopyMemory` + `MmIsAddressValid` 安全检查。

### DSE Control / DSE 开关控制 (`IO_DSE_*`)

Disable/enable Windows Driver Signature Enforcement at runtime by modifying `g_CiOptions` in CI.dll. Uses the [KDU](https://github.com/hfiref0x/KDU)-inspired method of locating `g_CiOptions` via `CiInitialize` export disassembly.

运行时启用/禁用 Windows 驱动签名强制（DSE），通过修改 CI.dll 中的 `g_CiOptions` 实现。使用 [KDU](https://github.com/hfiref0x/KDU) 的方法，通过反汇编 `CiInitialize` 导出函数精确定位 `g_CiOptions`。

---

## IOCTL Reference / IOCTL 接口

Device / 设备名: `\\.\KsDumper`

| IOCTL | Code | Description / 说明 |
|-------|------|--------------------|
| `IO_GET_PROCESS_LIST` | `0x1724` | Enumerate processes / 枚举进程 |
| `IO_COPY_MEMORY` | `0x1725` | Read process memory / 读进程内存 |
| `IO_UNLOAD_DRIVER` | `0x1726` | Unload driver / 卸载驱动 |
| `IO_WRITE_MEMORY` | `0x1727` | Write process memory / 写进程内存 |
| `IO_READ_KERNEL` | `0x1728` | Read kernel memory / 读内核内存 |
| `IO_DSE_SET_ADDR` | `0x1730` | Set g_CiOptions address / 设置 g_CiOptions 地址 |
| `IO_DSE_DISABLE` | `0x1731` | Disable DSE (g_CiOptions = 0) / 关闭 DSE |
| `IO_DSE_ENABLE` | `0x1732` | Restore DSE / 恢复 DSE |
| `IO_DSE_QUERY` | `0x1733` | Query DSE state / 查询 DSE 状态 |

---

## Data Structures / 数据结构

### KERNEL_COPY_MEMORY_OPERATION

Read/Write process memory. / 读写进程内存。

```c
typedef struct {
    INT32 targetProcessId;    // Target process ID / 目标进程 ID
    PVOID targetAddress;      // Address in target process / 目标进程中的地址
    PVOID bufferAddress;      // User-mode buffer / 用户态缓冲区
    INT32 bufferSize;         // Size / 大小
} KERNEL_COPY_MEMORY_OPERATION;
```

### KERNEL_READ_KERNEL_OPERATION

Read kernel-space memory. / 读内核空间内存。

```c
typedef struct {
    ULONG64 kernelAddress;    // Source in kernel space / 内核空间源地址
    PVOID   bufferAddress;    // User-mode destination / 用户态目标缓冲区
    INT32   bufferSize;       // Size (max 1MB) / 大小（最大 1MB）
} KERNEL_READ_KERNEL_OPERATION;
```

### KERNEL_DSE_OPERATION

DSE control. / DSE 控制。

```c
#define DSE_MAX_ADDRS 8

typedef struct {
    ULONG   count;                      // Number of addresses / 地址数量
    ULONG64 addresses[DSE_MAX_ADDRS];   // Kernel addresses / 内核地址
    ULONG   originals[DSE_MAX_ADDRS];   // Original values / 原始值
} KERNEL_DSE_OPERATION;
```

---

## DSE Client Tool / DSE 控制工具

`dse_client.exe` provides command-line DSE control.

`dse_client.exe` 提供命令行 DSE 控制功能。

```
dse_client.exe init             Find g_CiOptions / 定位 g_CiOptions
dse_client.exe query            Query DSE state / 查询 DSE 状态
dse_client.exe off              Disable DSE / 关闭 DSE
dse_client.exe on               Restore DSE / 恢复 DSE
dse_client.exe load <file.sys>  Init + Off + Load + On / 一键加载未签名驱动
```

### How g_CiOptions is located / g_CiOptions 定位原理

1. `NtQuerySystemInformation(SystemModuleInformation)` to find CI.dll kernel base / 获取 CI.dll 内核基址
2. `LoadLibraryEx` to map CI.dll in user-mode / 用户态映射 CI.dll
3. `GetProcAddress` to find `CiInitialize` export / 获取 `CiInitialize` 导出函数
4. Disassemble to find `call CipInitialize` (3+ param setup before `E8`) / 反汇编找到 `call CipInitialize`（`E8` 前有 3 个以上参数设置指令）
5. In `CipInitialize`, find first `mov [rip+disp32], r32` (`89 xx`, `ModRM & 0xC7 == 0x05`) / 在 `CipInitialize` 中找到第一个 `mov [rip+disp32], r32`
6. Calculate kernel address / 计算内核地址: `CI.dll_base + (file_offset - mapped_base)`

### Example / 示例

```bat
dse_client.exe load C:\path\to\unsigned.sys
```

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

---

## Build / 编译

### Driver / 驱动

Open `KsDumper11.sln` with Visual Studio 2019, build `KsDumperDriver` project (Release x64).

用 VS2019 打开 `KsDumper11.sln`，编译 `KsDumperDriver` 项目（Release x64）。

### DSE Client / DSE 客户端

```bat
cl /Fe:dse_client.exe dse_client.c advapi32.lib
```

---

## Files Changed / 修改文件

```
KsDumperDriver/
  Driver.c              + WriteVirtualMemory (MDL-based write)
                        + IO_WRITE_MEMORY handler
                        + IO_READ_KERNEL handler
                        + IO_DSE_SET_ADDR/DISABLE/ENABLE/QUERY handlers
                        + DseWriteAll (CR0.WP toggle at DISPATCH_LEVEL)

  UserModeBridge.h      + IO_WRITE_MEMORY, IO_READ_KERNEL defines
                        + IO_DSE_* defines
                        + KERNEL_READ_KERNEL_OPERATION struct
                        + KERNEL_DSE_OPERATION struct

dse_client.c            New / 新增 - DSE control tool / DSE 控制工具
```

---

## Safety / 安全说明

- DSE modification only touches one DWORD (`g_CiOptions`) / DSE 修改仅涉及一个 DWORD
- `MmIsAddressValid` check before every kernel memory access / 每次内核内存访问前检查有效性
- CR0.WP toggled at DISPATCH_LEVEL to prevent preemption / 在 DISPATCH_LEVEL 切换 CR0.WP 防止抢占
- Original value auto-restored on `dse_client.exe on` / 执行 `on` 时自动恢复原始值
- Write memory uses MDL + `__try/__except` for fault safety / 写内存使用 MDL + 异常保护

---

## Credits / 致谢

- Original KsDumper by [EquiFox](https://github.com/EquiFox/KsDumper)
- Windows 11 port by [mastercodeon314](https://github.com/mastercodeon314/KsDumper-11)
- DSE location method inspired by [KDU](https://github.com/hfiref0x/KDU) by hfiref0x
