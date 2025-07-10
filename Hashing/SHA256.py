import os
import hashlib
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import ttk
from tkinter import filedialog, messagebox, simpledialog
import sys
sys.path.append(r"C:\Users\kpkin\AppData\Local\Programs\Python\Python312\Lib\site-packages")
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyPDF2 import PdfReader, PdfWriter

# AES Encryption Key (Must be 16, 24, or 32 bytes long)
SECRET_KEY = b"thisisrysecureky"  # 16 bytes

IV = b"thisis16bytesiv1"  # Initialization Vector (16 bytes)


def generate_hash(file_path, algo="sha256"):
    """Generate hash (SHA-256 or MD5) of the given PDF file"""
    hash_func = hashlib.sha256() if algo == "sha256" else hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def encrypt_pdf(input_pdf, output_pdf, hash_output):
    """Encrypt the given PDF using AES encryption and generate hash"""
    with open(input_pdf, "rb") as f:
        pdf_data = f.read()

    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(pdf_data, AES.block_size))

    with open(output_pdf, "wb") as f:
        f.write(IV + encrypted_data)  # Store IV with encrypted file

    # Generate and save hash
    hash_value = generate_hash(input_pdf, "sha256")
    with open(hash_output, "w") as f:
        f.write(hash_value)

    return output_pdf, hash_value


def decrypt_pdf(input_pdf, output_pdf):
    """Decrypt the given encrypted PDF using AES"""
    with open(input_pdf, "rb") as f:
        encrypted_data = f.read()

    iv = encrypted_data[:16]  # Extract IV
    encrypted_content = encrypted_data[16:]

    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_content), AES.block_size)

    with open(output_pdf, "wb") as f:
        f.write(decrypted_data)

    return output_pdf


def verify_integrity(original_hash, received_pdf, algo="sha256"):
    """Verify the integrity of the received PDF by comparing hash values"""
    computed_hash = generate_hash(received_pdf, algo)
    return computed_hash == original_hash


# GUI for Selecting Files & Performing Operations
def select_pdf_encrypt():
    file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
    if file_path:
        encrypted_pdf = file_path.replace(".pdf", "_encrypted.pdf")
        hash_file = file_path.replace(".pdf", "_hash.txt")
        encrypted_pdf, hash_value = encrypt_pdf(file_path, encrypted_pdf, hash_file)

        messagebox.showinfo("Success",
                            f"PDF Encrypted!\nHash: {hash_value}\nSaved as {encrypted_pdf}\nHash saved in {hash_file}")


def select_pdf_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted PDF", "*_encrypted.pdf")])
    if file_path:
        decrypted_pdf = file_path.replace("_encrypted.pdf", "_decrypted.pdf")
        decrypt_pdf(file_path, decrypted_pdf)
        messagebox.showinfo("Success", f"PDF Decrypted!\nSaved as {decrypted_pdf}")


def verify_pdf():
    file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
    hash_file = filedialog.askopenfilename(filetypes=[("Text Files", "*_hash.txt")])

    if file_path and hash_file:
        with open(hash_file, "r") as f:
            original_hash = f.read().strip()

        is_valid = verify_integrity(original_hash, file_path, "sha256")
        if is_valid:
            messagebox.showinfo("Integrity Verified", "PDF is authentic! No modifications detected.")
        else:
            messagebox.showwarning("Warning!", "PDF has been modified! Alerting Exam Controller & Professor.")


# GUI Window Setup
root = tk.Tk()
root.title("Secure Question Paper PDF")
root.geometry("500x400")
root.configure(bg="#f0f0f0")

# === Stylish Heading ===
header = ttk.Label(
    root, text="SHA 256", font=("Arial", 18, "bold"), bootstyle="info"
)
header.pack(pady=10)

tk.Label(root, text="🔒 PDF Security System", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=15)

frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=10)

tk.Button(frame, text="🔐 Encrypt & Generate Hash", font=("Arial", 12), bg="#4CAF50", fg="white",
          command=select_pdf_encrypt, width=25).pack(pady=5)

tk.Button(frame, text="🔓 Decrypt PDF", font=("Arial", 12), bg="#008CBA", fg="white", command=select_pdf_decrypt,
          width=25).pack(pady=5)

tk.Button(frame, text="✔️ Verify Integrity", font=("Arial", 12), bg="#FF9800", fg="white", command=verify_pdf,
          width=25).pack(pady=5)

exit_button = tk.Button(root, text="❌ Exit", font=("Arial", 12), bg="#f44336", fg="white", command=root.quit, width=15)
exit_button.pack(pady=15)

root.mainloop()
