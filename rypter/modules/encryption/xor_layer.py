# modules/encryption/xor_layer.py

from typing import Optional


class XORLayer:
    """
    Chiffrement XOR symétrique.
    Utilisé comme première ou dernière couche légère d'obfuscation.
    """

    def __init__(self, key: Optional[bytearray] = None):
        """
        Initialise avec une clé XOR. Si aucune clé n’est fournie, une clé par défaut sera utilisée.
        :param key: clé XOR (bytearray)
        """
        self.key = key or bytearray(range(256))

    def encrypt(self, data: bytes) -> bytes:
        """
        Applique le chiffrement XOR.
        :param data: données à chiffrer (bytes)
        :return: données chiffrées (bytes)
        """
        result = bytearray()
        key_len = len(self.key)

        for i, byte in enumerate(data):
            result.append(byte ^ self.key[i % key_len])

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """
        Déchiffrement (identique à encrypt car XOR est symétrique).
        :param data: données chiffrées
        :return: données en clair
        """
        return self.encrypt(data)
