#include 
#include 

// Récupération dynamique des syscall IDs
DWORD GetSyscallID(PCHAR funcName) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    void* pFunc = GetProcAddress(hNtdll, funcName);
    return *(DWORD*)((BYTE*)pFunc + 4); // Offset du syscall ID
}

// NtAllocateVirtualMemory via syscall
NTSTATUS SysNtAllocateVirtualMemory(HANDLE hProcess, PVOID* base, SIZE_T size, ULONG protect) {
    NTSTATUS status;
    DWORD syscall = GetSyscallID("NtAllocateVirtualMemory");
    __asm {
        mov r10, rcx
        mov eax, syscall
        syscall
        mov status, eax
    }
    return status;
}

// NtCreateThreadEx via syscall
NTSTATUS SysNtCreateThreadEx(PHANDLE hThread, PVOID start, PVOID arg) {
    NTSTATUS status;
    DWORD syscall = GetSyscallID("NtCreateThreadEx");
    __asm {
        mov r10, rcx
        mov eax, syscall
        syscall
        mov status, eax
    }
    return status;
}