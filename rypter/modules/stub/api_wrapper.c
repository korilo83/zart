#include 

// Wrapper pour VirtualAlloc
PVOID CustomVirtualAlloc(SIZE_T size, ULONG protect) {
    PVOID base = NULL;
    HANDLE hProcess = GetCurrentProcess();
    SysNtAllocateVirtualMemory(hProcess, &base, &size, protect);
    return base;
}

// Wrapper pour CreateThread
HANDLE CustomCreateThread(PVOID start, PVOID arg) {
    HANDLE hThread = NULL;
    SysNtCreateThreadEx(&hThread, start, arg);
    return hThread;
}