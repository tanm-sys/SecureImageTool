import os
import tkinter as tk
import struct
import io
import hashlib
from tkinter import ttk, filedialog, messagebox
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
import platform

# Constants
HEADER_FORMAT = '!16sI12sIIBB'  # salt, iterations, nonce, width, height, mode_len, format_len
PBKDF_ITERATIONS = 2**20  # 1,048,576 iterations (adjust based on system capabilities)
MODE_NAMES = ['1', 'L', 'P', 'RGB', 'RGBA', 'CMYK', 'YCbCr', 'LAB', 'HSV', 'I', 'F']

class SecureImageCrypto:
    def __init__(self):
        self.current_operation = None

    def derive_key(self, password, salt, iterations):
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=iterations,
            r=8,
            p=1
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_image(self, input_path, password):
        try:
            with Image.open(input_path) as img:
                img_format = img.format or 'PNG'
                mode = img.mode
                
                if mode not in MODE_NAMES:
                    raise ValueError(f"Unsupported image mode: {mode}")

                # Generate cryptographic parameters
                salt = os.urandom(16)
                nonce = os.urandom(12)
                iterations = PBKDF_ITERATIONS

                # Derive encryption key
                key = self.derive_key(password, salt, iterations)
                aesgcm = AESGCM(key)

                # Convert image to bytes with metadata
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format=img_format)
                plaintext = img_byte_arr.getvalue()

                # Encrypt image data
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)

                # Prepare header with metadata lengths
                header = struct.pack(
                    HEADER_FORMAT,
                    salt,
                    iterations,
                    nonce,
                    img.width,
                    img.height,
                    len(mode),
                    len(img_format)
                )

                # Add encoded metadata
                metadata = mode.encode('utf-8') + img_format.encode('utf-8')

                return header + metadata + ciphertext

        except Exception as e:
            raise CryptoOperationError(f"Encryption failed: {str(e)}")

    def decrypt_image(self, encrypted_data, password):
        try:
            # Parse header
            header_size = struct.calcsize(HEADER_FORMAT)
            header = encrypted_data[:header_size]
            salt, iterations, nonce, width, height, mode_len, format_len = struct.unpack(HEADER_FORMAT, header)
            
            # Validate header values
            if iterations > PBKDF_ITERATIONS * 2:
                raise ValueError("Invalid iteration count")
            
            if mode_len > 10 or mode_len < 1 or format_len > 10 or format_len < 1:
                raise ValueError("Corrupted metadata information")

            # Extract metadata
            metadata_start = header_size
            metadata_end = metadata_start + mode_len + format_len
            metadata = encrypted_data[metadata_start:metadata_end]

            mode = metadata[:mode_len].decode('utf-8')
            img_format = metadata[mode_len:mode_len+format_len].decode('utf-8')

            # Derive decryption key
            key = self.derive_key(password, salt, iterations)
            aesgcm = AESGCM(key)

            # Decrypt image data
            ciphertext = encrypted_data[metadata_end:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            # Reconstruct image
            img = Image.open(io.BytesIO(plaintext))
            if img.size != (width, height) or img.mode != mode:
                raise ValueError("Image metadata mismatch")

            return img

        except InvalidTag:
            raise CryptoOperationError("Decryption failed - incorrect password or corrupted data")
        except Exception as e:
            raise CryptoOperationError(f"Decryption failed: {str(e)}")

class CryptoOperationError(Exception):
    pass

class ImageEncryptorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Image Cryptography Suite")
        self.geometry("800x600")
        self.configure(bg='#f0f0f0')
        self.style = ttk.Style()
        self.crypto = SecureImageCrypto()
        self.create_widgets()
        self.set_os_theme()

    def set_os_theme(self):
        system = platform.system()
        if system == 'Windows':
            self.tk.call('source', 'azure.tcl')
            self.tk.call('set_theme', 'dark')
        elif system == 'Darwin':
            self.style.theme_use('aqua')

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X)
        
        ttk.Label(header_frame, text="🔒 Secure Image Vault", 
                font=('Helvetica', 24, 'bold')).pack(pady=10)
        
        ttk.Label(header_frame, text="Military-grade AES-256-GCM Encryption",
                font=('Helvetica', 12)).pack()

        # Password entry
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(pady=20, fill=tk.X)
        
        ttk.Label(password_frame, text="Vault Key:", width=10).pack(side=tk.LEFT)
        self.password_entry = ttk.Entry(password_frame, show="•", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        self.show_password = tk.BooleanVar()
        ttk.Checkbutton(password_frame, text="Show", variable=self.show_password,
                      command=self.toggle_password).pack(side=tk.LEFT)

        # Operation buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        
        self.encrypt_btn = ttk.Button(
            btn_frame, text="Encrypt Image", command=self.start_encryption,
            style='Accent.TButton'
        )
        self.encrypt_btn.pack(side=tk.LEFT, padx=10)
        
        self.decrypt_btn = ttk.Button(
            btn_frame, text="Decrypt Image", command=self.start_decryption
        )
        self.decrypt_btn.pack(side=tk.LEFT, padx=10)

        # Status bar
        self.status_bar = ttk.Label(self, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Security indicators
        self.password_strength = ttk.Progressbar(main_frame, length=200)
        self.password_strength.pack(pady=10)
        self.password_entry.bind('<KeyRelease>', self.update_password_strength)

    def toggle_password(self):
        show = self.show_password.get()
        self.password_entry.config(show='' if show else '•')

    def update_password_strength(self, event):
        password = self.password_entry.get()
        strength = min(len(password) * 2, 100)
        self.password_strength['value'] = strength

    def start_encryption(self):
        self._perform_operation('encrypt')

    def start_decryption(self):
        self._perform_operation('decrypt')

    def _perform_operation(self, operation):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Security Alert", "Vault key cannot be empty")
            return
        
        file_path = filedialog.askopenfilename(
            title=f"Select {'Image' if operation == 'encrypt' else 'Encrypted File'}",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg")] if operation == 'encrypt' 
                     else [("Encrypted Files", "*.enc")]
        )
        
        if not file_path:
            return
        
        try:
            self._disable_ui()
            if operation == 'encrypt':
                encrypted_data = self.crypto.encrypt_image(file_path, password)
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".enc",
                    filetypes=[("Encrypted File", "*.enc")]
                )
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(encrypted_data)
                    messagebox.showinfo("Success", 
                        f"Image secured at:\n{save_path}\n\nSHA-256: {self._calculate_hash(encrypted_data)}")
            else:
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_img = self.crypto.decrypt_image(encrypted_data, password)
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    filetypes=[("PNG Image", "*.png"), ("JPEG Image", "*.jpg")]
                )
                if save_path:
                    decrypted_img.save(save_path)
                    messagebox.showinfo("Success", "Image restored successfully!")
            
        except CryptoOperationError as e:
            messagebox.showerror("Security Error", str(e))
        except Exception as e:
            messagebox.showerror("System Error", f"Unexpected error: {str(e)}")
        finally:
            self._enable_ui()

    def _calculate_hash(self, data):
        return hashlib.sha256(data).hexdigest()

    def _disable_ui(self):
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        self.status_bar.config(text="Processing...")
        self.update()

    def _enable_ui(self):
        self.encrypt_btn.config(state=tk.NORMAL)
        self.decrypt_btn.config(state=tk.NORMAL)
        self.status_bar.config(text="Ready")
        self.update()

if __name__ == "__main__":
    app = ImageEncryptorGUI()
    app.mainloop()
