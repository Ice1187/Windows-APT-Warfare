#include <Windows.h>
#include <stdio.h>
#include "../myStruct32.h"
 
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
 
int main(void) {
    HANDLE hKernel32 = getModHandle(L"kernel32.dll");
    printf("kernel32 base: %x\n", hKernel32);
 
    size_t pWinExec = (size_t)GetProcAddress(hKernel32, "WinExec");
    if (pWinExec == 0) {fprintf(stderr, "GetProcAddress failed, error: %d\n", GetLastError()); return 1;}
    ((UINT(WINAPI*)(LPCSTR, UINT))pWinExec)("calc", SW_SHOW);
 
    return 0;
}
