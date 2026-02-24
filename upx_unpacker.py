import os
import sys
import subprocess
import requests
import zipfile
import pefile
import customtkinter as ctk
from tkinter import filedialog, messagebox

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

UPX_NAME = "upx.exe"
UPX_URL = "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-win64.zip"

class UPXUnpacker(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("666 UPX UNPACKER")
        self.geometry("600x450")
        
        self.setup_ui()
        self.check_upx_exists()

    def setup_ui(self):
        self.header_label = ctk.CTkLabel(self, text="UPX UNPACKER", font=ctk.CTkFont(size=24, weight="bold"))
        self.header_label.pack(pady=20)

        self.file_frame = ctk.CTkFrame(self)
        self.file_frame.pack(pady=10, padx=20, fill="x")

        self.file_entry = ctk.CTkEntry(self.file_frame, placeholder_text="Select File to Unpack...")
        self.file_entry.pack(side="left", padx=10, pady=10, expand=True, fill="x")

        self.browse_button = ctk.CTkButton(self.file_frame, text="BROWSE", command=self.browse_file)
        self.browse_button.pack(side="right", padx=10, pady=10)

        self.info_frame = ctk.CTkFrame(self)
        self.info_frame.pack(pady=10, padx=20, fill="x")

        self.info_label = ctk.CTkLabel(self.info_frame, text="Packer Status: Unknown", font=ctk.CTkFont(size=14))
        self.info_label.pack(pady=10)

        self.btn_frame = ctk.CTkFrame(self)
        self.btn_frame.pack(pady=10, padx=20, fill="x")

        self.check_button = ctk.CTkButton(self.btn_frame, text="CHECK FILE", command=self.check_file)
        self.check_button.pack(side="left", padx=10, pady=10, expand=True)

        self.unpack_button = ctk.CTkButton(self.btn_frame, text="UNPACK", command=self.unpack_file, fg_color="#A30000", hover_color="#660000")
        self.unpack_button.pack(side="right", padx=10, pady=10, expand=True)

        self.log_text = ctk.CTkTextbox(self, height=100)
        self.log_text.pack(pady=10, padx=20, fill="both", expand=True)
        self.log_text.configure(state="disabled")

    def log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"> {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def check_upx_exists(self):
        if not os.path.exists(UPX_NAME):
            self.log("upx.exe not found in local directory.")
            if messagebox.askyesno("Missing UPX", "upx.exe is required for unpacking. Download it automatically?"):
                self.download_upx()
        else:
            self.log("Ready: upx.exe is present.")

    def download_upx(self):
        self.log("Downloading UPX...")
        try:
            r = requests.get(UPX_URL)
            with open("upx_dist.zip", "wb") as f:
                f.write(r.content)
            
            with zipfile.ZipFile("upx_dist.zip", "r") as zip_ref:
                for name in zip_ref.namelist():
                    if name.endswith("upx.exe"):
                        with zip_ref.open(name) as source, open(UPX_NAME, "wb") as target:
                            target.write(source.read())
                        break
            
            os.remove("upx_dist.zip")
            self.log("UPX downloaded and extracted successfully.")
        except Exception as e:
            self.log(f"Download failed: {str(e)}")
            messagebox.showerror("Error", f"Failed to download UPX: {str(e)}")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)
            self.check_file()

    def check_file(self):
        path = self.file_entry.get()
        if not os.path.exists(path):
            return

        try:
            pe = pefile.PE(path)
            is_upx = False
            for section in pe.sections:
                name = section.Name.decode().strip('\x00')
                if "UPX" in name:
                    is_upx = True
                    break
            
            if is_upx:
                self.info_label.configure(text="Packer Status: UPX DETECTED", text_color="#FF0000")
                self.log(f"Detected UPX headers in {os.path.basename(path)}")
            else:
                self.info_label.configure(text="Packer Status: NO UPX FOUND", text_color="#00FF00")
                self.log("No obvious UPX sections found.")
            
            pe.close()
        except Exception as e:
            self.log(f"Error checking file: {str(e)}")

    def unpack_file(self):
        path = self.file_entry.get()
        if not os.path.exists(path):
            messagebox.showwarning("Error", "Please select a valid file.")
            return

        if not os.path.exists(UPX_NAME):
            self.log("Cannot unpack: upx.exe is missing.")
            return

        self.log(f"Attempting to unpack {os.path.basename(path)}...")
        try:
            result = subprocess.run([UPX_NAME, "-d", path], capture_output=True, text=True)
            if result.returncode == 0:
                self.log("Successfully unpacked!")
                messagebox.showinfo("Success", "File has been unpacked.")
            else:
                self.log(f"UPX Error: {result.stderr}")
                messagebox.showerror("Unpack Failed", result.stderr)
        except Exception as e:
            self.log(f"Error: {str(e)}")

if __name__ == "__main__":
    app = UPXUnpacker()
    app.mainloop()
