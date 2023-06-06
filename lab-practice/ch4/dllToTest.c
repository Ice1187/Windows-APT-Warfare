/*
 * dllToTest.c
 * $ gcc -static --shared dllToTest.c -o demo.dll
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 *
 * modify by ice1187 2023/06/06
 */

#include <Windows.h>
 
char message[256] = "Top Secret!";
 
__declspec(dllexport) void func1() {MessageBoxA(0, message, "func1", 0);}
__declspec(dllexport) void func2() {MessageBoxA(0, message, "func2", 0);}
__declspec(dllexport) void func3() {MessageBoxA(0, message, "func3", 0);}
 
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        strcpy(message, "Hello Hackers!");
        return TRUE;
    }
}
 
void DoNothing() {Sleep(1000);}
 
__declspec(dllexport) void func4() {MessageBoxA(0, message, "func4", 0);}
__declspec(dllexport) void func5() {MessageBoxA(0, message, "func5", 0);}
