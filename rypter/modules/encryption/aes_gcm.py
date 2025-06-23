# modules/encryption/aes_gcm.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .keygen import KeyGenerator

class AESGCMEncryption:
    def __init__(self, key=None):
        self.key = key or KeyGenerator.generate_random_key(32)
        self.cipher = AESGCM(self.key)
        
    def encrypt(self, data, associated_data=None):
        """Chiffrement AES-GCM avec authentification"""
        nonce = KeyGenerator.generate_nonce()
        ciphertext = self.cipher.encrypt(nonce, data, associated_data)
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'key': self.key
        }
        
    def decrypt(self, encrypted_data, associated_data=None):
        """Déchiffrement AES-GCM"""
        return self.cipher.decrypt(
            encrypted_data['nonce'],
            encrypted_data['ciphertext'],
            associated_data
        )