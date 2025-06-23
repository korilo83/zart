import os
import pefile

class PayloadPreparer:
    def __init__(self):
        self.supported_formats = ['.exe', '.dll', '.bin']

    def prepare(self, payload_path):
        """Prépare un payload pour le chiffrement et l'obfuscation."""
        if not os.path.exists(payload_path):
            raise FileNotFoundError(f"[❌] Fichier introuvable : {payload_path}")

        ext = os.path.splitext(payload_path)[1].lower()

        if ext in ['.exe', '.dll']:
            return self._prepare_pe(payload_path)
        elif ext == '.bin':
            return self._prepare_raw(payload_path)
        else:
            raise ValueError(f"[❌] Format non supporté : {ext}")

    def _prepare_pe(self, pe_path):
        """Analyse un fichier PE (.exe/.dll)"""
        try:
            pe = pefile.PE(pe_path)

            if not pe.is_exe() and not pe.is_dll():
                raise ValueError("[❌] Fichier PE invalide.")

            with open(pe_path, 'rb') as f:
                data = f.read()

            arch = 'x64' if pe.OPTIONAL_HEADER.Magic == 0x20B else 'x86'

            metadata = {
                'type': 'PE',
                'arch': arch,
                'size': len(data),
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'is_dll': pe.is_dll(),
                'imports': self._extract_imports(pe)
            }

            return {
                'data': data,
                'metadata': metadata,
                'original_path': pe_path
            }

        except Exception as e:
            raise Exception(f"[❌] Analyse PE échouée : {e}")

    def _prepare_raw(self, raw_path):
        """Prépare un shellcode brut"""
        with open(raw_path, 'rb') as f:
            data = f.read()

        metadata = {
            'type': 'RAW',
            'size': len(data),
            'arch': 'unknown'
        }

        return {
            'data': data,
            'metadata': metadata,
            'original_path': raw_path
        }

    def _extract_imports(self, pe):
        """🧠 Extract DLLs/API imports (optionnel, pour analyse future)"""
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore')
                funcs = [imp.name.decode(errors='ignore') for imp in entry.imports if imp.name]
                imports.append({'dll': dll, 'functions': funcs})
        return imports
