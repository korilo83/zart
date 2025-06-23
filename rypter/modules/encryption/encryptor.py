# modules/encryption/encryptor.py
from .aes_gcm import AESGCMEncryption
from .xor_layer import XORLayer
from .compressor import Compressor
from .keygen import KeyGenerator

class EncryptionCoordinator:
    def __init__(self, method="AES-GCM"):
        self.method = method
        
    def encrypt_payload(self, payload_data):
        """Coordonne le processus de chiffrement"""
        data = payload_data['data']
        
        # Phase 1: Compression
        compressed = Compressor.compress_lzma(data)
        
        if self.method == "AES-GCM":
            return self._encrypt_aes_gcm(compressed)
        elif self.method == "AES-CBC+XOR":
            return self._encrypt_hybrid(compressed)
        elif self.method == "Triple Layer":
            return self._encrypt_triple_layer(compressed)
        else:
            raise ValueError(f"Unknown encryption method: {self.method}")
            
    def _encrypt_aes_gcm(self, data):
        """Chiffrement AES-GCM simple"""
        aes = AESGCMEncryption()
        result = aes.encrypt(data)
        
        keys = {
            'aes_key': result['key'],
            'nonce': result['nonce'],
            'method': 'AES-GCM'
        }
        
        return result['ciphertext'], keys
        
    def _encrypt_hybrid(self, data):
        """Chiffrement hybride AES + XOR"""
        # Layer 1: XOR
        xor_key = KeyGenerator.generate_xor_key(256)
        xor = XORLayer(xor_key)
        xor_encrypted = xor.encrypt(data)
        
        # Layer 2: AES-GCM
        aes = AESGCMEncryption()
        aes_result = aes.encrypt(xor_encrypted)
        
        keys = {
            'xor_key': xor_key,
            'aes_key': aes_result['key'],
            'nonce': aes_result['nonce'],
            'method': 'Hybrid'
        }
        
        return aes_result['ciphertext'], keys
        
    def _encrypt_triple_layer(self, data):
        """Triple chiffrement pour évasion maximale"""
        # Layer 1: XOR simple
        xor1_key = KeyGenerator.generate_xor_key(128)
        xor1 = XORLayer(xor1_key)
        layer1 = xor1.encrypt(data)
        
        # Layer 2: AES-GCM
        aes = AESGCMEncryption()
        aes_result = aes.encrypt(layer1)
        
        # Layer 3: XOR avec clé différente
        xor2_key = KeyGenerator.generate_xor_key(256)
        xor2 = XORLayer(xor2_key)
        layer3 = xor2.encrypt(aes_result['ciphertext'])
        
        keys = {
            'xor1_key': xor1_key,
            'aes_key': aes_result['key'],
            'nonce': aes_result['nonce'],
            'xor2_key': xor2_key,
            'method': 'Triple'
        }
        
        return layer3, keys