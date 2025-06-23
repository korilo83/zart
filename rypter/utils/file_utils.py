# utils/file_utils.py
import os
import shutil
import hashlib
import zipfile

class FileUtils:
    @staticmethod
    def copy_file(src, dst):
        """Copie un fichier"""
        shutil.copy2(src, dst)
        
    @staticmethod
    def calculate_hash(file_path, algorithm='sha256'):
        """Calcule le hash d'un fichier"""
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
        
    @staticmethod
    def compress_directory(dir_path, output_path):
        """Compresse un dossier en ZIP"""
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, dir_path)
                    zipf.write(file_path, arcname)
                    
    @staticmethod
    def clean_temp_files(directory):
        """Nettoie les fichiers temporaires"""
        temp_extensions = ['.tmp', '.temp', '.log']
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in temp_extensions):
                    try:
                        os.remove(os.path.join(root, file))
                    except:
                        pass
                        
    @staticmethod
    def secure_delete(file_path, passes=3):
        """Suppression sécurisée d'un fichier"""
        if not os.path.exists(file_path):
            return
            
        filesize = os.path.getsize(file_path)
        
        with open(file_path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(filesize))
                f.flush()
                os.fsync(f.fileno())
                
        os.remove(file_path)
