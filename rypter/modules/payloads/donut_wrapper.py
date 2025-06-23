# modules/payloads/donut_wrapper.py
import subprocess
import os
import tempfile

class DonutWrapper:
    def __init__(self):
        self.donut_path = self._find_donut()
        
    def _find_donut(self):
        # Recherche de donut.exe dans le PATH ou dossier local
        for path in ["donut.exe", "./tools/donut.exe", "C:\\Tools\\donut.exe"]:
            if os.path.exists(path):
                return path
        raise FileNotFoundError("Donut not found. Please install donut.")
        
    def convert_to_shellcode(self, pe_path, arch="x64", output_format="raw"):
        """Convertit un PE en shellcode via Donut"""
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
            output_path = tmp.name
            
        cmd = [
            self.donut_path,
            "-f", pe_path,
            "-a", arch,
            "-o", output_path
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            with open(output_path, 'rb') as f:
                shellcode = f.read()
                
            os.unlink(output_path)
            return shellcode
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Donut conversion failed: {e.stderr}")
