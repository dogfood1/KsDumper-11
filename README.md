# KsDumper-11 Enhanced

Fork of [KsDumper-11](https://github.com/mastercodeon314/KsDumper-11) with added **Write Memory**, **Kernel Memory Read**, and **DSE Control** capabilities.

## New Features

### Write Process Memory (`IO_WRITE_MEMORY`)

Write arbitrary data to any process's virtual memory using MDL-based mapping. Handles write-protected pages via `MmProtectMdlSystemAddress`.

### Read Kernel Memory (`IO_READ_KERNEL`)

Directly read kernel-space addresses (e.g., CI.dll, ntoskrnl data sections) from user-mode. Uses `RtlCopyMemory` with `MmIsAddressValid` safety checks.

### DSE Control (`IO_DSE_*`)

Disable/enable Windows Driver Signature Enforcement at runtime by modifying `g_CiOptions` in CI.dll. Uses the [KDU](https://github.com/hfiref0x/KDU)-inspired method of locating `g_CiOptions` via `CiInitialize` export disassembly.

## IOCTL Reference

Device: `\\.\KsDumper`

| IOCTL | Code | Method | Description |
|-------|------|--------|-------------|
| `IO_GET_PROCESS_LIST` | `0x1724` | Buffered | Enumerate running processes |
| `IO_COPY_MEMORY` | `0x1725` | Buffered | Read process memory |
| `IO_UNLOAD_DRIVER` | `0x1726` | Buffered | Unload driver and cleanup |
| `IO_WRITE_MEMORY` | `0x1727` | Buffered | Write process memory |
| `IO_READ_KERNEL` | `0x1728` | Buffered | Read kernel-space memory |
| `IO_DSE_SET_ADDR` | `0x1730` | Buffered | Set g_CiOptions address(es) |
| `IO_DSE_DISABLE` | `0x1731` | Buffered | Set g_CiOptions = 0 |
| `IO_DSE_ENABLE` | `0x1732` | Buffered | Restore g_CiOptions |
| `IO_DSE_QUERY` | `0x1733` | Buffered | Query current DSE state |

## Data Structures

### KERNEL_COPY_MEMORY_OPERATION (Read/Write Memory)

```c
typedef struct {
    INT32 targetProcessId;
    PVOID targetAddress;
    PVOID bufferAddress;
    INT32 bufferSize;
} KERNEL_COPY_MEMORY_OPERATION;
```

### KERNEL_READ_KERNEL_OPERATION (Read Kernel Memory)

```c
typedef struct {
    ULONG64 kernelAddress;    // Source address in kernel space
    PVOID   bufferAddress;    // Destination buffer in user space
    INT32   bufferSize;       // Size to read (max 1MB)
} KERNEL_READ_KERNEL_OPERATION;
```

### KERNEL_DSE_OPERATION (DSE Control)

```c
#define DSE_MAX_ADDRS 8

typedef struct {
    ULONG   count;                      // Number of addresses
    ULONG64 addresses[DSE_MAX_ADDRS];   // Kernel addresses of CI options
    ULONG   originals[DSE_MAX_ADDRS];   // Original/current values
} KERNEL_DSE_OPERATION;
```

## DSE Client Tool

`dse_client.exe` provides command-line DSE control using the KDU method to locate `g_CiOptions`:

```
dse_client.exe init             Find g_CiOptions via CiInitialize disassembly
dse_client.exe query            Query current DSE state
dse_client.exe off              Disable DSE (g_CiOptions = 0)
dse_client.exe on               Restore DSE to original value
dse_client.exe load <file.sys>  Init + Off + Load driver + On
```

### How g_CiOptions is located

1. `NtQuerySystemInformation(SystemModuleInformation)` to find CI.dll kernel base
2. `LoadLibraryEx` to map CI.dll in user-mode
3. `GetProcAddress` to find `CiInitialize` export
4. Disassemble `CiInitialize` to find `call CipInitialize` (identified by 3+ parameter setup instructions before `E8` opcode)
5. Disassemble `CipInitialize` to find first `mov [rip+disp32], r32` (opcode `89 xx` where `ModRM & 0xC7 == 0x05`)
6. Calculate kernel address: `CI.dll_base + (file_offset - mapped_base)`

### Example: Load unsigned driver

```bat
dse_client.exe load C:\path\to\unsigned.sys
```

Output:
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

## Build

### Driver

Open `KsDumper11.sln` with Visual Studio 2019, build the `KsDumperDriver` project (Release x64).

### DSE Client

```bat
cl /Fe:dse_client.exe dse_client.c advapi32.lib
```

## Files Changed

```
KsDumperDriver/
  Driver.c              + WriteVirtualMemory function
                        + IO_WRITE_MEMORY IOCTL handler
                        + IO_READ_KERNEL IOCTL handler
                        + IO_DSE_SET_ADDR/DISABLE/ENABLE/QUERY handlers
                        + DseWriteAll helper (CR0.WP toggle at DISPATCH_LEVEL)

  UserModeBridge.h      + IO_WRITE_MEMORY, IO_READ_KERNEL IOCTL defines
                        + IO_DSE_* IOCTL defines
                        + KERNEL_READ_KERNEL_OPERATION struct
                        + KERNEL_DSE_OPERATION struct

dse_client.c            New file - user-mode DSE control tool
```

## Safety Notes

- DSE modification only touches one DWORD (`g_CiOptions`)
- `MmIsAddressValid` check before every kernel memory access
- CR0.WP toggled at DISPATCH_LEVEL to prevent thread preemption
- Original value auto-restored on `dse_client.exe on` or `IO_DSE_ENABLE`
- Write memory uses MDL mapping with `__try/__except` for fault safety

## Credits

- Original KsDumper by [EquiFox](https://github.com/EquiFox/KsDumper)
- Windows 11 port by [mastercodeon314](https://github.com/mastercodeon314/KsDumper-11)
- DSE location method inspired by [KDU](https://github.com/hfiref0x/KDU) by hfiref0x
