#include <Windows.h>
#include <stdio.h>
#include "../myStruct32.h"
 
#define getNtHdrs(pe) ((IMAGE_NT_HEADERS*)((size_t)pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew))
 
HANDLE getModHandle(const WCHAR* libname) {
    PEB* peb = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock;
    struct _LIST_ENTRY* head = &(peb->Ldr->InLoadOrderModuleList);
    for (struct _LIST_ENTRY* cur = head; cur->Flink != head; cur = cur->Flink) {
        // Get module BaseDllName
        LDR_DATA_TABLE_ENTRY* pldr_data = (LDR_DATA_TABLE_ENTRY*)cur;
        printf("Module Name: %S\n", pldr_data->BaseDllName.Buffer);
 
        // Get module handle
        if (!_wcsicmp(pldr_data->BaseDllName.Buffer, libname)) {
            return pldr_data->DllBase;
        }
    }
}
 
size_t myGetProcAddr(size_t modulebase, char* funcname) {
    IMAGE_EXPORT_DIRECTORY* exportTable = (IMAGE_EXPORT_DIRECTORY*)(modulebase + getNtHdrs(modulebase)->OptionalHeader.DataDirectory[0].VirtualAddress);
    size_t numOfNames = exportTable->NumberOfNames;
    DWORD* addrOfNames = (DWORD*)(modulebase + exportTable->AddressOfNames);
    WORD* addrOfOrdinals = (WORD*)(modulebase + exportTable->AddressOfNameOrdinals);
    DWORD* addrOfFuncs = (DWORD*)(modulebase + exportTable->AddressOfFunctions);
 
    char* curName;
    for (size_t i = 0; i < numOfNames; i++) {
        if(!stricmp(funcname, (char*)(modulebase + addrOfNames[i]))) {
            size_t ordinalIdx = addrOfOrdinals[i];
            size_t funcAddr = modulebase + addrOfFuncs[ordinalIdx];
            return funcAddr;
        }
    }
 
    printf("%s not found\n", funcname);
    return 0;
}
 
int main(void) {
    size_t kernel32Base = (size_t)getModHandle(L"kernel32.dll");
    printf("kernel32 base: %x\n", kernel32Base);
 
    size_t pWinExec = (size_t)myGetProcAddr(kernel32Base, "WinExec");
    if (pWinExec == 0) {fprintf(stderr, "GetProcAddress failed, error: %d\n", GetLastError()); return 1;}
    ((UINT(WINAPI*)(LPCSTR, UINT))pWinExec)("calc", SW_SHOW);
 
 
    return 0;
}
