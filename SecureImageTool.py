import os
from tkinter import Tk, Entry, Label, Button, Canvas, Message
from tkinter.filedialog import askopenfilename, asksaveasfilename
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import tkinter.messagebox as tkMessageBox
import tkinter as tk

# ---------------------
# GUI stuff starts here
# ---------------------

def pass_alert():
    tkMessageBox.showinfo("Password Alert", "Please enter a password.")

def enc_success(imagename):
    tkMessageBox.showinfo("Success", f"Encrypted Image: {imagename}")

def image_open():
    global file_path_e

    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(enc_pass.encode()).digest()
        filename = askopenfilename()
        file_path_e = os.path.dirname(filename)
        encrypt_image(filename, password)

def cipher_open():
    global file_path_d

    dec_pass = passg.get()
    if dec_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(dec_pass.encode()).digest()
        filename = askopenfilename()
        file_path_d = os.path.dirname(filename)
        decrypt_image(filename, password)

def encrypt_image(filename, password):
    # Open the image file
    img = Image.open(filename)
    img_data = img.tobytes()

    # Get the image dimensions
    width, height = img.size

    # AES encryption setup
    cipher = AES.new(password, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(img_data, AES.block_size))

    # Save the encrypted image (including the IV for decryption, and the dimensions)
    output_filename = asksaveasfilename(defaultextension=".enc")
    with open(output_filename, 'wb') as f:
        # Save the image dimensions (width and height)
        f.write(width.to_bytes(4, 'big'))
        f.write(height.to_bytes(4, 'big'))
        f.write(cipher.iv)  # Save the IV to the file
        f.write(encrypted_data)
    
    enc_success(os.path.basename(output_filename))

def decrypt_image(filename, password):
    # Open the encrypted file
    with open(filename, 'rb') as f:
        # Read the image dimensions (width and height)
        width = int.from_bytes(f.read(4), 'big')
        height = int.from_bytes(f.read(4), 'big')

        # Read the IV and encrypted data
        iv = f.read(16)  # AES block size is 16 bytes
        encrypted_data = f.read()

    # AES decryption setup
    cipher = AES.new(password, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Convert the decrypted data back to an image
    img = Image.frombytes('RGB', (width, height), decrypted_data)

    # Save the decrypted image
    output_filename = asksaveasfilename(defaultextension=".png")
    img.save(output_filename)

# Tkinter GUI setup
root = Tk()
title = "Image Encryption"
author = "Made by Aditya"

msgtitle = Message(root, text=title)
msgtitle.config(font=('helvetica', 17, 'bold'), width=200)

msgauthor = Message(root, text=author)
msgauthor.config(font=('helvetica', 10), width=200)

canvas_width = 200
canvas_height = 50

w = Canvas(root, width=canvas_width, height=canvas_height)
w.pack()

Label(root, text="Password: ").pack(side=tk.LEFT)  # Correct usage of tk.LEFT
passg = Entry(root, show="*")
passg.pack(side=tk.LEFT)

Button(root, text="Encrypt", command=image_open).pack(side=tk.TOP)
Button(root, text="Decrypt", command=cipher_open).pack(side=tk.BOTTOM)

root.mainloop()
