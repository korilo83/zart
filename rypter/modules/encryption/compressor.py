# modules/encryption/compressor.py

import lzma
import zlib
import gzip
from typing import Literal


class Compressor:
    """
    Fournit plusieurs algorithmes de compression : LZMA, zlib, gzip.
    Utilisé pour réduire la taille du payload avant chiffrement.
    """

    @staticmethod
    def compress(data: bytes, method: Literal["lzma", "zlib", "gzip"] = "lzma", level: int = 6) -> bytes:
        """
        Compresse les données avec l'algorithme spécifié.
        :param data: Données à compresser
        :param method: Méthode de compression ('lzma', 'zlib', 'gzip')
        :param level: Niveau de compression (1-9)
        :return: Données compressées
        """
        if method == "lzma":
            return lzma.compress(data, preset=level)
        elif method == "zlib":
            return zlib.compress(data, level)
        elif method == "gzip":
            return gzip.compress(data, compresslevel=level)
        else:
            raise ValueError(f"Méthode de compression non supportée : {method}")

    @staticmethod
    def decompress(data: bytes, method: Literal["lzma", "zlib", "gzip"]) -> bytes:
        """
        Décompresse les données selon l'algorithme.
        :param data: Données compressées
        :param method: Méthode utilisée ('lzma', 'zlib', 'gzip')
        :return: Données originales
        """
        if method == "lzma":
            return lzma.decompress(data)
        elif method == "zlib":
            return zlib.decompress(data)
        elif method == "gzip":
            return gzip.decompress(data)
        else:
            raise ValueError(f"Méthode de décompression non supportée : {method}")
