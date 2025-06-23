# modules/encryption/compressor.py
import lzma
import zlib
import gzip

class Compressor:
    @staticmethod
    def compress_lzma(data, preset=6):
        """Compression LZMA (meilleur ratio)"""
        return lzma.compress(data, preset=preset)
        
    @staticmethod
    def decompress_lzma(data):
        """Décompression LZMA"""
        return lzma.decompress(data)
        
    @staticmethod
    def compress_zlib(data, level=6):
        """Compression zlib (plus rapide)"""
        return zlib.compress(data, level)
        
    @staticmethod
    def decompress_zlib(data):
        """Décompression zlib"""
        return zlib.decompress(data)
        
    @staticmethod
    def compress_gzip(data, level=6):
        """Compression gzip"""
        return gzip.compress(data, compresslevel=level)
