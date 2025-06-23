# modules/encryption/aes_gcm.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .keygen import KeyGenerator


class AESGCMEncryption:
    """
    Classe de chiffrement AES-GCM avec authentification intégrée.
    Fournit un chiffrement/déchiffrement sécurisé avec clé et nonce aléatoires.
    """

    def __init__(self, key: bytes = None):
        """
        Initialise un chiffreur AES-GCM.
        :param key: clé AES 256 bits (32 bytes) sinon générée automatiquement
        """
        self.key = key or KeyGenerator.generate_random_key(32)
        self.cipher = AESGCM(self.key)

    def encrypt(self, data: bytes, associated_data: bytes = None) -> dict:
        """
        Chiffre des données en AES-GCM.
        :param data: données en clair à chiffrer (bytes)
        :param associated_data: données associées pour authentification (facultatif)
        :return: dict contenant le ciphertext, nonce et clé
        """
        nonce = KeyGenerator.generate_nonce()
        ciphertext = self.cipher.encrypt(nonce, data, associated_data)

        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "key": self.key
        }

    def decrypt(self, encrypted_data: dict, associated_data: bytes = None) -> bytes:
        """
        Déchiffre un bloc AES-GCM.
        :param encrypted_data: dict contenant 'ciphertext' et 'nonce'
        :param associated_data: facultatif
        :return: données déchiffrées en clair
        """
        return self.cipher.decrypt(
            encrypted_data["nonce"],
            encrypted_data["ciphertext"],
            associated_data
        )
