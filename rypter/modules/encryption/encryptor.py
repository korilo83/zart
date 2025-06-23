# modules/encryption/encryptor.py

from .aes_gcm import AESGCMEncryption
from .xor_layer import XORLayer
from .compressor import Compressor
from .keygen import KeyGenerator


class EncryptionCoordinator:
    """
    Gère l'enchaînement des couches de chiffrement : compression, XOR, AES-GCM.
    Trois modes disponibles :
    - AES-GCM seul
    - AES-CBC + XOR
    - Triple Layer : XOR → AES → XOR
    """

    def __init__(self, method="AES-GCM"):
        self.method = method

    def encrypt_payload(self, payload_data):
        """
        Lance le chiffrement du payload selon la méthode spécifiée.
        :param payload_data: dict avec champ 'data' en bytes
        :return: (ciphertext: bytes, keys: dict)
        """
        data = payload_data.get("data")
        if not data:
            raise ValueError("Données à chiffrer manquantes dans 'payload_data'.")

        compressed = Compressor.compress_lzma(data)

        if self.method == "AES-GCM":
            return self._encrypt_aes_gcm(compressed)

        elif self.method == "AES-CBC+XOR":
            return self._encrypt_hybrid(compressed)

        elif self.method == "Triple Layer":
            return self._encrypt_triple_layer(compressed)

        else:
            raise ValueError(f"[❌] Méthode inconnue : {self.method}")

    def _encrypt_aes_gcm(self, data):
        """Chiffrement AES-GCM simple (rapide, sûr, compatible)"""
        aes = AESGCMEncryption()
        result = aes.encrypt(data)

        return result["ciphertext"], {
            "aes_key": result["key"],
            "nonce": result["nonce"],
            "method": "AES-GCM"
        }

    def _encrypt_hybrid(self, data):
        """Chiffrement XOR (obfuscation) suivi de AES-GCM"""
        xor_key = KeyGenerator.generate_xor_key(256)
        xor = XORLayer(xor_key)
        xor_encrypted = xor.encrypt(data)

        aes = AESGCMEncryption()
        aes_result = aes.encrypt(xor_encrypted)

        return aes_result["ciphertext"], {
            "xor_key": xor_key,
            "aes_key": aes_result["key"],
            "nonce": aes_result["nonce"],
            "method": "Hybrid"
        }

    def _encrypt_triple_layer(self, data):
        """Chiffrement triple : XOR (obfuscation) → AES → XOR"""
        xor1_key = KeyGenerator.generate_xor_key(128)
        xor1 = XORLayer(xor1_key)
        layer1 = xor1.encrypt(data)

        aes = AESGCMEncryption()
        aes_result = aes.encrypt(layer1)

        xor2_key = KeyGenerator.generate_xor_key(256)
        xor2 = XORLayer(xor2_key)
        layer3 = xor2.encrypt(aes_result["ciphertext"])

        return layer3, {
            "xor1_key": xor1_key,
            "aes_key": aes_result["key"],
            "nonce": aes_result["nonce"],
            "xor2_key": xor2_key,
            "method": "Triple"
        }
