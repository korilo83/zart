# modules/encryption/keygen.py
import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class KeyGenerator:
    @staticmethod
    def generate_random_key(length=32):
        """Génère une clé aléatoire cryptographiquement sûre"""
        return secrets.token_bytes(length)
        
    @staticmethod
    def generate_nonce(length=12):
        """Génère un nonce pour AES-GCM"""
        return secrets.token_bytes(length)
        
    @staticmethod
    def derive_key_from_password(password, salt, length=32):
        """Dérive une clé depuis un mot de passe"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
        
    @staticmethod
    def generate_xor_key(length):
        """Génère une clé XOR"""
        return bytearray([secrets.randbelow(256) for _ in range(length)])