#include <Windows.h>
#include <stdio.h>
#include "../myStruct32.h"
 
UNICODE_STRING new_name_ustr, new_full_name_ustr;
 
int wchar2UnicodeString(UNICODE_STRING* pUstr, WCHAR* wstr) {
    pUstr->Length = wcslen(wstr)*2; 
    pUstr->MaximumLength = pUstr->Length + 2;
    pUstr->Buffer = calloc(1, pUstr->MaximumLength);
    wcsncpy(pUstr->Buffer, wstr, wcslen(wstr));
    return 0;
}
 
int renameDynModule(const WCHAR* libname) {
    WCHAR new_name[] = L"exploit.dll";
    WCHAR new_full_name[] = L"C:\\Windows3\\System32\\exploit.dll";
 
    PEB* peb = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock;
    LIST_ENTRY* head = &(peb->Ldr->InLoadOrderModuleList);
    for (LIST_ENTRY* cur = head; cur->Flink != head; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY* ldr_entry = (LDR_DATA_TABLE_ENTRY*)cur;
        if (!wcsicmp(ldr_entry->BaseDllName.Buffer, libname)) {
            wchar2UnicodeString(&new_name_ustr, new_name);
            wchar2UnicodeString(&new_full_name_ustr, new_full_name);
            ldr_entry->BaseDllName = new_name_ustr;
            ldr_entry->FullDllName = new_full_name_ustr;
            printf("New BaseDllName: %ls\n", ldr_entry->BaseDllName.Buffer);
            printf("New FullDllName: %ls\n", ldr_entry->FullDllName.Buffer);
         
            break;
        }
    }
}
 
int main(void) {
    renameDynModule(L"kernel32.dll");
 
    printf("Go into sleep...\n");
    Sleep(10000);
 
    free(new_name_ustr.Buffer);
    free(new_full_name_ustr.Buffer);
 
    return 0;
}
