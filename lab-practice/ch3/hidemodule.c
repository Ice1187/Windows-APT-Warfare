#include <Windows.h>
#include <stdio.h>
#include "../myStruct32.h"
 
int hideModule(const WCHAR* libname) {
    PEB* peb = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock;
    struct _LIST_ENTRY* head = &(peb->Ldr->InLoadOrderModuleList);
    for (struct _LIST_ENTRY* cur = head; cur->Flink != head; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY* ldr_entry = (LDR_DATA_TABLE_ENTRY*)cur;
        if (!wcsicmp(ldr_entry->BaseDllName.Buffer, libname)) {
            struct _LIST_ENTRY* prev, *next;
            // Load Order
            prev = (struct _LIST_ENTRY*)(ldr_entry->InLoadOrderLinks.Blink);
            next = (struct _LIST_ENTRY*)(ldr_entry->InLoadOrderLinks.Flink);
            prev->Flink = next;
            next->Blink = prev;
            // Memory Order
            prev = (struct _LIST_ENTRY*)(ldr_entry->InMemoryOrderLinks.Blink);
            next = (struct _LIST_ENTRY*)(ldr_entry->InMemoryOrderLinks.Flink);
            prev->Flink = next;
            next->Blink = prev;
            // Init Order
            prev = (struct _LIST_ENTRY*)(ldr_entry->InInitializationOrderLinks.Blink);
            next = (struct _LIST_ENTRY*)(ldr_entry->InInitializationOrderLinks.Flink);
            prev->Flink = next;
            next->Blink = prev;
            break;
        }
    }
}
 
int findModule(const WCHAR* libname) {
    PEB* peb = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock;
    struct _LIST_ENTRY* head = &(peb->Ldr->InLoadOrderModuleList);
    for (struct _LIST_ENTRY* cur = head; cur->Flink != head; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY* ldr_entry = (LDR_DATA_TABLE_ENTRY*)cur;
        if (!wcsicmp(ldr_entry->BaseDllName.Buffer, libname)) {
            printf("Found module %ls at %x\n", ldr_entry->BaseDllName.Buffer, ldr_entry->DllBase);
            return 0;
        }
    }
    printf("Module %ls not found\n", libname);
}
 
int main(void) {
    WCHAR target_lib[] = L"kernel32.dll";
    findModule(target_lib);
    hideModule(target_lib);
    printf("[!] Module hide\n");
    findModule(target_lib);
 
    return 0;
}
