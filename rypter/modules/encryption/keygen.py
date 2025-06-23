# modules/encryption/keygen.py

import secrets
from typing import Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class KeyGenerator:
    """
    Utilitaire de génération de clés cryptographiques :
    - AES keys
    - Nonces
    - Clés XOR
    - Dérivation de clés depuis un mot de passe
    """

    @staticmethod
    def generate_random_key(length: int = 32) -> bytes:
        """
        Génère une clé cryptographiquement sûre.
        :param length: longueur en octets (ex: 32 pour AES-256)
        :return: clé en bytes
        """
        return secrets.token_bytes(length)

    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        """
        Génère un nonce aléatoire (typique pour AES-GCM).
        :param length: longueur recommandée = 12 octets
        :return: nonce en bytes
        """
        return secrets.token_bytes(length)

    @staticmethod
    def derive_key_from_password(password: str, salt: Union[str, bytes], length: int = 32) -> bytes:
        """
        Dérive une clé depuis un mot de passe avec PBKDF2 + SHA256.
        :param password: mot de passe utilisateur
        :param salt: sel unique
        :param length: taille souhaitée (ex: 32 pour AES-256)
        :return: clé dérivée
        """
        if isinstance(salt, str):
            salt = salt.encode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(password.encode())

    @staticmethod
    def generate_xor_key(length: int) -> bytearray:
        """
        Génère une clé XOR aléatoire.
        :param length: longueur souhaitée
        :return: clé sous forme de bytearray
        """
        return bytearray(secrets.randbelow(256) for _ in range(length))
