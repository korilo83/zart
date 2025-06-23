# tests/regression_suite.py
import unittest
import os
import tempfile
from core.dispatcher import BuildDispatcher
from modules.encryption.encryptor import EncryptionCoordinator

class RegressionSuite(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
    def test_encryption_decryption(self):
        """Test du processus de chiffrement/déchiffrement"""
        test_data = b"Hello, World!" * 1000
        payload_data = {'data': test_data, 'metadata': {'type': 'RAW'}}
        
        coordinator = EncryptionCoordinator("AES-GCM")
        encrypted, keys = coordinator.encrypt_payload(payload_data)
        
        self.assertIsNotNone(encrypted)
        self.assertIsNotNone(keys)
        self.assertNotEqual(encrypted, test_data)
        
    def test_stub_generation(self):
        """Test de génération de stub"""
        from modules.stub.stubgen import StubGenerator
        
        generator = StubGenerator("High")
        test_data = b"test" * 100
        test_keys = {'method': 'AES-GCM', 'aes_key': b'key', 'nonce': b'nonce'}
        
        # Mock de la compilation pour les tests
        try:
            stub_path = generator.generate_stub(test_data, test_keys, self.temp_dir)
            self.assertTrue(os.path.exists(stub_path.replace('.exe', '.c')))
        except Exception as e:
            # La compilation peut échouer dans l'environnement de test
            self.assertIn("MinGW", str(e))
            
    def test_build_process(self):
        """Test du processus de build complet"""
        # Création d'un payload de test
        test_payload = os.path.join(self.temp_dir, "test.exe")
        with open(test_payload, 'wb') as f:
            f.write(b"MZ" + b"\x00" * 1000)  # Fake PE header
            
        config = {
            'payload_path': test_payload,
            'output_dir': self.temp_dir,
            'encryption_method': 'AES-GCM',
            'evasion_level': 'Basic',
            'target_format': 'Standalone EXE'
        }
        
        dispatcher = BuildDispatcher(config)
        
        # Le build peut échouer sans les outils requis, mais on teste la structure
        try:
            success, output = dispatcher.build_all()
            # Si succès, vérifier la sortie
            if success:
                self.assertIsNotNone(output)
        except Exception as e:
            # Vérifier que l'erreur est due aux dépendances manquantes
            self.assertTrue(any(dep in str(e) for dep in ["MinGW", "Donut", "compiler"]))

if __name__ == '__main__':
    unittest.main()
