import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

# AES Encryption function
def encrypt_file(input_file, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    encrypted_file = input_file + ".enc"
    with open(encrypted_file, 'wb') as f:
        f.write(base64.b64encode(salt + iv + ciphertext))
    
    return encrypted_file

# AES Decryption function
def decrypt_file(input_file, password):
    with open(input_file, 'rb') as f:
        encrypted_data = base64.b64decode(f.read())
    
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    decrypted_file = input_file.replace(".enc", "_decrypted.txt")
    with open(decrypted_file, 'wb') as f:
        f.write(plaintext)
    
    return decrypted_file

# Hacker-inspired UI
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption/Decryption")
        self.root.geometry("700x500")
        self.root.config(bg="#0f0f0f")  # Dark background for a hacker look

        # Title label with monospaced font for terminal effect
        self.title_label = tk.Label(root, text="Encryption/Decryption", font=("Courier New", 22, "bold"), fg="#00ff00", bg="#0f0f0f")
        self.title_label.pack(pady=20)

        # Password input label with a modern font
        self.password_label = tk.Label(root, text="Enter Password:", font=("Courier New", 14), fg="#00ff00", bg="#0f0f0f")
        self.password_label.pack(pady=5)

        # Password entry with terminal style
        self.password_entry = tk.Entry(root, show="*", font=("Courier New", 14), width=30, relief="flat", bd=0, bg="#1a1a1a", fg="#00ff00")
        self.password_entry.pack(pady=5)

        # File selection buttons with neon style
        self.select_file_button = tk.Button(root, text="Select File to Encrypt", command=self.select_file_for_encryption, font=("Courier New", 14), bg="#00ff00", fg="black", relief="raised", bd=0, width=20)
        self.select_file_button.pack(pady=10)

        self.select_file_button_decrypt = tk.Button(root, text="Select File to Decrypt", command=self.select_file_for_decryption, font=("Courier New", 14), bg="#ff3300", fg="black", relief="raised", bd=0, width=20)
        self.select_file_button_decrypt.pack(pady=10)

        # Encrypt and Decrypt buttons with neon style
        self.encrypt_button = tk.Button(root, text="Encrypt File", command=self.encrypt_file_gui, font=("Courier New", 14), bg="#0099cc", fg="black", relief="raised", bd=0, width=20, state=tk.DISABLED)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(root, text="Decrypt File", command=self.decrypt_file_gui, font=("Courier New", 14), bg="#ffcc00", fg="black", relief="raised", bd=0, width=20, state=tk.DISABLED)
        self.decrypt_button.pack(pady=10)

        # File display label with neon green text
        self.file_label = tk.Label(root, text="No file selected", font=("Courier New", 14), fg="#00ff00", bg="#0f0f0f")
        self.file_label.pack(pady=20)

        # Variables to store selected files
        self.selected_file = None

    def select_file_for_encryption(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.file_label.config(text=f"Selected file: {self.selected_file}")
            self.encrypt_button.config(state=tk.NORMAL)

    def select_file_for_decryption(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.file_label.config(text=f"Selected file: {self.selected_file}")
            self.decrypt_button.config(state=tk.NORMAL)

    def encrypt_file_gui(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file to encrypt.")
            return
        
        try:
            encrypted_file = encrypt_file(self.selected_file, password)
            messagebox.showinfo("Success", f"File encrypted successfully: {encrypted_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file_gui(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file to decrypt.")
            return
        
        try:
            decrypted_file = decrypt_file(self.selected_file, password)
            messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
