import os
import shutil
import threading
import tkinter as tk
from tkinter import Tk, Entry, Label, Button, Canvas, Message, ttk
from tkinter.filedialog import askopenfilename, asksaveasfilename
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import tkinter.messagebox as tkMessageBox

# ------------------------
# Advanced AES Image Encryptor with Corruption Handling
# ------------------------

class AESImageEncryptor:
    def __init__(self, password: str):
        """Initialize with a password, generate salt and derive key."""
        self.password = password
        self.salt = get_random_bytes(16)  # Random salt for PBKDF2
        self.key = self.derive_key()

    def derive_key(self):
        """Derive a 256-bit encryption key from the password using PBKDF2."""
        return PBKDF2(self.password.encode(), self.salt, dkLen=32, count=1000000)

    def encrypt_image(self, filename: str, output_filename: str):
        """Encrypt the image using AES-GCM."""
        # Read the image and convert to raw bytes
        img = Image.open(filename)
        img_data = img.tobytes()
        
        # Save the original image's format, width, and height for later use
        img_format = img.format
        img_width, img_height = img.size
        
        # Generate a nonce for AES-GCM (12 bytes)
        nonce = get_random_bytes(12)
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        encrypted_data, tag = cipher.encrypt_and_digest(pad(img_data, AES.block_size))
        
        # Write the encrypted image data to a file
        with open(output_filename, "wb") as enc_file:
            enc_file.write(self.salt)  # Save salt for key derivation
            enc_file.write(nonce)  # Save nonce for decryption
            enc_file.write(tag)  # Save the authentication tag
            enc_file.write(img_width.to_bytes(4, 'big'))  # Store image width
            enc_file.write(img_height.to_bytes(4, 'big'))  # Store image height
            enc_file.write(img_format.encode())  # Store image format (e.g., 'PNG', 'JPEG')
            enc_file.write(encrypted_data)  # Store the encrypted image data
        
        return img_width, img_height, img_format

    def decrypt_image(self, filename: str, output_filename: str):
        """Decrypt the image using AES-GCM with integrity verification."""
        try:
            with open(filename, "rb") as enc_file:
                salt = enc_file.read(16)  # Read the salt used for key derivation
                nonce = enc_file.read(12)  # Read the nonce for AES-GCM
                tag = enc_file.read(16)  # Read the authentication tag
                img_width = int.from_bytes(enc_file.read(4), "big")  # Read image width
                img_height = int.from_bytes(enc_file.read(4), "big")  # Read image height
                img_format = enc_file.read(4).decode()  # Read the image format
                encrypted_data = enc_file.read()  # Read the encrypted image data

            # Derive the key from the password and salt
            self.salt = salt
            self.key = self.derive_key()

            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = unpad(cipher.decrypt_and_verify(encrypted_data, tag), AES.block_size)
            
            # Convert the decrypted bytes back into an image
            img = Image.frombytes("RGB", (img_width, img_height), decrypted_data)
            
            # Save the decrypted image in its original format
            img.save(output_filename, format=img_format)
            return True  # Decryption successful

        except (ValueError, KeyError, IOError) as e:
            self.handle_decryption_error(e)
            return False  # Decryption failed

    def handle_decryption_error(self, error):
        """Handle errors during decryption and notify the user."""
        if isinstance(error, ValueError):
            # This could indicate corrupted data or incorrect password
            tkMessageBox.showerror("Decryption Failed", "The file could be corrupted or the password is incorrect.")
        elif isinstance(error, KeyError):
            # This could indicate an issue with reading file or missing data
            tkMessageBox.showerror("Decryption Failed", "File corruption detected or missing data.")
        elif isinstance(error, IOError):
            # This could indicate an issue saving the image (incorrect format or file issues)
            tkMessageBox.showerror("Decryption Failed", "There was an issue saving the image file.")
        else:
            tkMessageBox.showerror("Error", f"Decryption error: {str(error)}")

    def backup_image(self, filename: str):
        """Backup the image before encryption/decryption."""
        backup_filename = filename + ".backup"
        shutil.copy2(filename, backup_filename)
        return backup_filename


# ------------------------
# Tkinter GUI Setup with Corruption Recovery
# ------------------------

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Image Encryption Tool")

        # Password input field
        Label(self.root, text="Password: ").pack(side=tk.LEFT)
        self.passg = Entry(self.root, show="*")
        self.passg.pack(side=tk.LEFT)

        # Buttons for encryption and decryption
        Button(self.root, text="Encrypt", command=self.encrypt_image).pack(side=tk.TOP)
        Button(self.root, text="Decrypt", command=self.decrypt_image).pack(side=tk.BOTTOM)

        # Progress bar and status label
        self.status_label = Label(self.root, text="Ready", font=('helvetica', 12))
        self.status_label.pack(side=tk.BOTTOM)

        self.progress = ttk.Progressbar(self.root, orient='horizontal', length=200, mode='indeterminate')
        self.progress.pack(side=tk.BOTTOM)

    def update_status(self, message):
        """Update the status label."""
        self.status_label.config(text=message)

    def show_error(self, message):
        """Show error message."""
        tkMessageBox.showerror("Error", message)

    def encrypt_image(self):
        """Handle image encryption process."""
        password = self.passg.get()
        if not password or len(password) < 8:
            self.show_error("Password is required and should be at least 8 characters.")
            return

        # Ask the user to select an image file
        filename = askopenfilename(title="Select Image to Encrypt")
        if filename:
            output_filename = asksaveasfilename(defaultextension=".enc", title="Save Encrypted Image")
            if output_filename:
                # Create AESImageEncryptor instance and encrypt the image
                encryptor = AESImageEncryptor(password)
                img_width, img_height, img_format = encryptor.encrypt_image(filename, output_filename)
                self.update_status(f"Encrypted image saved to {output_filename} in {img_format} format")

    def decrypt_image(self):
        """Handle image decryption process."""
        password = self.passg.get()
        if not password or len(password) < 8:
            self.show_error("Password is required and should be at least 8 characters.")
            return

        # Ask the user to select an encrypted image file
        filename = askopenfilename(title="Select Encrypted Image")
        if filename:
            # Backup the original encrypted file before attempting decryption
            backup_filename = self.backup_file(filename)
            
            output_filename = asksaveasfilename(defaultextension=".png", title="Save Decrypted Image")
            if output_filename:
                try:
                    # Create AESImageEncryptor instance and decrypt the image
                    encryptor = AESImageEncryptor(password)
                    success = encryptor.decrypt_image(filename, output_filename)
                    
                    if success:
                        self.update_status(f"Decrypted image saved to {output_filename}")
                    else:
                        self.update_status("Decryption failed. Restoring from backup.")
                        shutil.copy2(backup_filename, filename)  # Restore the backup
                except Exception as e:
                    self.show_error(f"Error: {str(e)}")

    def backup_file(self, filename):
        """Create a backup of the encrypted file."""
        backup_filename = filename + ".backup"
        shutil.copy2(filename, backup_filename)
        return backup_filename


# Run the Tkinter application
root = Tk()
app = ImageEncryptorApp(root)
root.mainloop()
