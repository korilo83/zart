# modules/stub/compiler.py
import subprocess
import os
import tempfile

class DynamicCompiler:
    def __init__(self):
        self.gcc_path = self._find_gcc()
        
    def _find_gcc(self):
        """Trouve le compilateur MinGW-GCC"""
        possible_paths = [
            "gcc.exe",
            "x86_64-w64-mingw32-gcc.exe",
            "i686-w64-mingw32-gcc.exe",
            "C:\\mingw64\\bin\\gcc.exe",
            "C:\\msys64\\mingw64\\bin\\gcc.exe"
        ]
        
        for path in possible_paths:
            try:
                subprocess.run([path, "--version"], capture_output=True, check=True)
                return path
            except:
                continue
                
        raise FileNotFoundError("MinGW-GCC not found. Please install MinGW.")
        
    def compile_stub(self, source_path, output_dir):
        """Compile le stub C en exécutable"""
        output_path = os.path.join(output_dir, "stub.exe")
        
        compile_cmd = [
            self.gcc_path,
            "-o", output_path,
            source_path,
            "-static",
            "-O2",
            "-s",  # Strip symbols
            "-fno-stack-protector",
            "-Wl,--subsystem,windows",  # Windows subsystem
            "-ladvapi32"  # Registry functions
        ]
        
        try:
            result = subprocess.run(compile_cmd, capture_output=True, text=True, check=True)
            return output_path
        except subprocess.CalledProcessError as e:
            raise Exception(f"Compilation failed: {e.stderr}")