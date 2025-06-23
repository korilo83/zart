# modules/payloads/payload_preparer.py
import pefile
import os

class PayloadPreparer:
    def __init__(self):
        self.supported_formats = ['.exe', '.dll', '.bin']
        
    def prepare(self, payload_path):
        """Prépare le payload pour le chiffrement"""
        if not os.path.exists(payload_path):
            raise FileNotFoundError(f"Payload not found: {payload_path}")
            
        ext = os.path.splitext(payload_path)[1].lower()
        
        if ext in ['.exe', '.dll']:
            return self._prepare_pe(payload_path)
        elif ext == '.bin':
            return self._prepare_raw(payload_path)
        else:
            raise ValueError(f"Unsupported payload format: {ext}")
            
    def _prepare_pe(self, pe_path):
        """Analyse et prépare un fichier PE"""
        try:
            pe = pefile.PE(pe_path)
            
            # Vérifications de base
            if not pe.is_exe() and not pe.is_dll():
                raise ValueError("Invalid PE file")
                
            # Lecture des données
            with open(pe_path, 'rb') as f:
                data = f.read()
                
            # Métadonnées
            metadata = {
                'type': 'PE',
                'arch': 'x64' if pe.OPTIONAL_HEADER.Magic == 0x20b else 'x86',
                'size': len(data),
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'is_dll': pe.is_dll()
            }
            
            return {
                'data': data,
                'metadata': metadata,
                'original_path': pe_path
            }
            
        except Exception as e:
            raise Exception(f"PE analysis failed: {str(e)}")
            
    def _prepare_raw(self, raw_path):
        """Prépare un shellcode raw"""
        with open(raw_path, 'rb') as f:
            data = f.read()
            
        metadata = {
            'type': 'RAW',
            'size': len(data)
        }
        
        return {
            'data': data,
            'metadata': metadata,
            'original_path': raw_path
        }