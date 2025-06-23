# modules/encryption/xor_layer.py
class XORLayer:
    def __init__(self, key=None):
        self.key = key or bytearray(range(256))
        
    def encrypt(self, data):
        """Chiffrement XOR simple"""
        result = bytearray()
        key_len = len(self.key)
        
        for i, byte in enumerate(data):
            result.append(byte ^ self.key[i % key_len])
            
        return bytes(result)
        
    def decrypt(self, data):
        """Le XOR est symétrique"""
        return self.encrypt(data)
