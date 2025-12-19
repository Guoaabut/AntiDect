# apiHash
使用apiHash动态调用api，避免显示调用api函数名和隐藏导出表
利用PEB结构直接获取ntdll基地址NtdllBase
通过获取的NtdllBase+e_lfanew得到NtHandle
在export导出表中遍历函数名比对hash得到目标api
## getModuleByHash
- **获取PEB基地址**通过访问gs寄存器\x60偏移得到PEB进程环境块的地址
```c
        PPEB GetPeb64_Asm() {
    PPEB peb;
    __asm__ volatile (
        "movq %%gs:0x60, %0"
        : "=r" (peb)
    );
    return peb;
    }
```
- 通过PEB访问Ldr(加载器)数据结构
- Ldr中有三个双向链表,它们记录了加载dll的不同顺序，我们使用InMemoryOrderModuleList链表，获取dll在内存中的加载顺序
```c
    PLIST_ENTRY listHead = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY listEntry = listHead->Flink;
```
- **遍历返回ntdll基地址**使用CONTAINING_RECORD宏遍历获取完整的LDR_DATA_TABLE_ENTRY结构,这里包含了dll的完整信息,并比对entry->BaseDllName成员的值的hash是否等于目标hash,返回dll的基地址
```c
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
```
## GetProcAddressByHash
- **获取Nt头**NtdllBase的基地址即为DosHandle的起始地址，通过DosHandle中的e_lfanew字段获取指向NtHandle的偏移
```c
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
```

- **获取导出表结构**通过OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddres获取导出表的RVA,在通过运算得出导出的VA
导出表有三个重要字段
1. pExport->AddressOfNames //导出函数名称表，即有名称的函数的列表，我们通过遍历它获取所有带名称的api  
2. pExport->AddressOfFunctions //导出表中的函数的地址表  
3. pExport->AddressOfNameOrdinals //函数的序号，通过该序号取出对应函数的地址  
```c
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

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
```
## typedef funcs
- 最后通过typedef定义函数结构，调用GetProcAddressByHash取得目标函数地址
```c
    typedef NTSTATUS (NTAPI *fnvc)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG PageProtection
    );
    fnvc pVitualMem = (fnvc)GetProcAddressByHash(
        dllBase, 
        0x38B83169
    );
```



