"""
encryptor.py: A tool to keep files private using AES-256-GCM encryption.
"""

import os
import sys
import base64
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Set up where logs go and which files we shouldn't touch
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryption_log.txt")

BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".so", ".dylib",
    ".bat", ".cmd", ".sh", ".bin"
}

# This unique header helps us identify files we have already processed
MAGIC_HEADER = b"ENCRYPTD"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def is_encrypted(path):
    # Check the first 8 bytes for our specific magic header
    try:
        with open(path, "rb") as f:
            return f.read(8) == MAGIC_HEADER
    except Exception:
        return False

def validate_file(path):
    # Safety checks to ensure we are working with a valid, non-system file
    if not os.path.exists(path):
        return "File not found."
    if not os.path.isfile(path):
        return "Path is not a file."
    if os.path.getsize(path) == 0:
        return "File is empty."
    ext = os.path.splitext(path)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        return f"Blocked file type: '{ext}'"
    return None

def encrypt_file(path):
    err = validate_file(path)
    if err:
        return False, err
    if is_encrypted(path):
        return False, "File is already encrypted by this tool."

    with open(path, "rb") as f:
        plaintext = f.read()

    # Create a random 256-bit key and a unique nonce for this specific session
    key   = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    try:
        # Overwrite the file with the header, nonce, and the actual encrypted data
        with open(path, "wb") as f:
            f.write(MAGIC_HEADER + nonce + ciphertext)
    except Exception as e:
        # If writing fails, try to put the original content back
        with open(path, "wb") as f:
            f.write(plaintext)
        return False, f"Write failed, file restored: {e}"

    logging.info(f"ENCRYPTED | {path}")
    key_b64 = base64.urlsafe_b64encode(key).decode()
    return True, key_b64

def decrypt_file(path, key_b64):
    if not os.path.exists(path):
        return False, "File not found."
    if not is_encrypted(path):
        return False, "This file was not encrypted by this tool."

    try:
        key = base64.urlsafe_b64decode(key_b64)
        if len(key) != 32:
            raise ValueError
    except Exception:
        return False, "Invalid key format."

    with open(path, "rb") as f:
        data = f.read()

    # Pull the nonce and ciphertext out from after the 8-byte header
    nonce      = data[8:20]
    ciphertext = data[20:]

    try:
        aesgcm    = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return False, "Decryption failed, wrong key or corrupted file."

    try:
        with open(path, "wb") as f:
            f.write(plaintext)
    except Exception as e:
        return False, f"Could not write file: {e}"

    logging.info(f"DECRYPTED | {path}")
    return True, "File decrypted successfully."

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Encryptor")
        self.resizable(False, False)
        self.configure(bg="#f0f0f0")
        self._selected_file = tk.StringVar(value="No file selected")
        self._build_ui()
        self._center()

    def _center(self):
        # Position the window in the middle of the user's screen
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build_ui(self):
        # Construct the visual layout and buttons
        pad = {"padx": 16, "pady": 8}

        tk.Label(
            self, text="File Encryptor", font=("Helvetica", 16, "bold"),
            bg="#f0f0f0", fg="#222"
        ).grid(row=0, column=0, columnspan=3, pady=(16, 4))

        tk.Label(
            self, text="AES-256-GCM  •  In-place encryption",
            font=("Helvetica", 9), bg="#f0f0f0", fg="#888"
        ).grid(row=1, column=0, columnspan=3, pady=(0, 12))

        tk.Label(self, text="Selected file:", bg="#f0f0f0", anchor="w")\
            .grid(row=2, column=0, sticky="w", padx=16)

        tk.Entry(
            self, textvariable=self._selected_file,
            width=42, state="readonly", relief="solid",
            readonlybackground="white", fg="#444"
        ).grid(row=3, column=0, columnspan=2, padx=(16, 4), pady=(0, 4), sticky="w")

        tk.Button(
            self, text="Browse…", width=10,
            command=self._browse, relief="solid", cursor="hand2"
        ).grid(row=3, column=2, padx=(0, 16), pady=(0, 4))

        tk.Frame(self, height=1, bg="#ccc")\
            .grid(row=4, column=0, columnspan=3, sticky="ew", padx=16, pady=8)

        tk.Label(self, text="Encrypt", font=("Helvetica", 11, "bold"),
                 bg="#f0f0f0").grid(row=5, column=0, sticky="w", padx=16)

        tk.Button(
            self, text="Encrypt File", width=16, bg="#2c7be5", fg="white",
            activebackground="#1a5bbf", relief="flat", cursor="hand2",
            font=("Helvetica", 10, "bold"), command=self._encrypt
        ).grid(row=6, column=0, sticky="w", padx=16, pady=(4, 0))

        tk.Label(self, text="Key will appear below after encryption.",
                 bg="#f0f0f0", fg="#666", font=("Helvetica", 9))\
            .grid(row=6, column=1, columnspan=2, sticky="w")

        tk.Label(self, text="Decryption key, save this:",
                 bg="#f0f0f0", anchor="w")\
            .grid(row=7, column=0, columnspan=3, sticky="w", padx=16, pady=(8, 2))

        self._key_var = tk.StringVar()
        key_entry = tk.Entry(
            self, textvariable=self._key_var, width=56,
            font=("Courier", 9), relief="solid", state="readonly",
            readonlybackground="#fffbe6", fg="#333"
        )
        key_entry.grid(row=8, column=0, columnspan=2, padx=(16, 4), pady=(0, 4), sticky="w")

        tk.Button(
            self, text="Copy", width=10, relief="solid", cursor="hand2",
            command=self._copy_key
        ).grid(row=8, column=2, padx=(0, 16))

        tk.Frame(self, height=1, bg="#ccc")\
            .grid(row=9, column=0, columnspan=3, sticky="ew", padx=16, pady=8)

        tk.Label(self, text="Decrypt", font=("Helvetica", 11, "bold"),
                 bg="#f0f0f0").grid(row=10, column=0, sticky="w", padx=16)

        tk.Label(self, text="Paste your decryption key:",
                 bg="#f0f0f0", anchor="w")\
            .grid(row=11, column=0, columnspan=3, sticky="w", padx=16, pady=(8, 2))

        self._dec_key_var = tk.StringVar()
        tk.Entry(
            self, textvariable=self._dec_key_var, width=56,
            font=("Courier", 9), relief="solid"
        ).grid(row=12, column=0, columnspan=2, padx=(16, 4), pady=(0, 8), sticky="w")

        tk.Button(
            self, text="Decrypt File", width=16, bg="#28a745", fg="white",
            activebackground="#1e7e34", relief="flat", cursor="hand2",
            font=("Helvetica", 10, "bold"), command=self._decrypt
        ).grid(row=13, column=0, sticky="w", padx=16, pady=(0, 4))

        tk.Frame(self, height=1, bg="#ccc")\
            .grid(row=14, column=0, columnspan=3, sticky="ew", padx=16, pady=8)

        tk.Label(self, text="Encryption Log", font=("Helvetica", 11, "bold"),
                 bg="#f0f0f0").grid(row=15, column=0, sticky="w", padx=16)

        self._log_box = scrolledtext.ScrolledText(
            self, width=58, height=6, state="disabled",
            font=("Courier", 8), relief="solid", bg="white"
        )
        self._log_box.grid(row=16, column=0, columnspan=3, padx=16, pady=(4, 4), sticky="w")

        tk.Button(
            self, text="Refresh Log", relief="solid", cursor="hand2",
            command=self._load_log
        ).grid(row=17, column=0, sticky="w", padx=16, pady=(0, 16))

        self._load_log()

    def _browse(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self._selected_file.set(path)
            self._key_var.set("")

    def _encrypt(self):
        path = self._selected_file.get()
        if path == "No file selected":
            messagebox.showwarning("No file", "Please select a file first.")
            return
        ok, result = encrypt_file(path)
        if ok:
            self._key_var.set(result)
            messagebox.showinfo(
                "Encrypted",
                "File encrypted successfully!\n\nYour decryption key is shown in the key box.\nSave it as it will not be stored anywhere."
            )
            self._load_log()
        else:
            messagebox.showerror("Error", result)

    def _decrypt(self):
        path = self._selected_file.get()
        if path == "No file selected":
            messagebox.showwarning("No file", "Please select a file first.")
            return
        key = self._dec_key_var.get().strip()
        if not key:
            messagebox.showwarning("No key", "Please paste your decryption key.")
            return
        ok, msg = decrypt_file(path, key)
        if ok:
            messagebox.showinfo("Decrypted", msg)
            self._load_log()
        else:
            messagebox.showerror("Error", msg)

    def _copy_key(self):
        key = self._key_var.get()
        if key:
            self.clipboard_clear()
            self.clipboard_append(key)
            messagebox.showinfo("Copied", "Key copied to clipboard.")
        else:
            messagebox.showwarning("No key", "No key to copy yet.")

    def _load_log(self):
        # Read the log file and show the last 50 entries in the UI
        self._log_box.config(state="normal")
        self._log_box.delete("1.0", tk.END)
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()
            for line in lines[-50:]:
                self._log_box.insert(tk.END, line)
            self._log_box.see(tk.END)
        else:
            self._log_box.insert(tk.END, "No log entries yet.")
        self._log_box.config(state="disabled")

if __name__ == "__main__":
    app = App()
    app.mainloop()
