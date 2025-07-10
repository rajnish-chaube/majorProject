import os
import re
import random
import hashlib
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from xml.sax.saxutils import escape
from cryptography.fernet import Fernet
from PyPDF2 import PdfReader, PdfWriter
import sys
sys.path.append(r"C:\Users\kpkin\AppData\Local\Programs\Python\Python312\Lib\site-packages")
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# AES Constants
SECRET_KEY = b"thisisrysecureky"  # 16 bytes
IV = b"thisis16bytesiv1"

# === Main Window ===
root = ttk.Window(themename="cyborg")
root.title("Secure Question Paper Generation")
root.geometry("2200x1800")

notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# ======================== Secure Paper Generator ========================
gen_frame = ttk.Frame(notebook)
notebook.add(gen_frame, text="📝 Generator")

questionslist, filename, colist = [], "", []
encryption_key = Fernet.generate_key()
fernet = Fernet(encryption_key)

status_label_gen = ttk.Label(gen_frame, text="📝 Ready", font=("Arial", 12), bootstyle="primary")
status_label_gen.pack(pady=10)


def get_question_count():
    return simpledialog.askinteger("Question Count",
                                   "Enter number of questions to generate:",
                                   minvalue=5, maxvalue=20)


def filechooser():
    global filename
    filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if filename:
        status_label_gen.config(text="✔ Questions File Selected!", bootstyle="success")

def cofilechooser():
    global colist
    cofile = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if cofile:
        with open(cofile, 'r') as f:
            colist.clear()
            colist.extend([line.strip() for line in f if line.strip()])
        status_label_gen.config(text="✔ CO File Selected!", bootstyle="success")


def processfile():
    global questionslist
    with open(filename, 'r', encoding='utf-8') as file:
        text = file.read()
    pattern = r"##(.*?)##\s*([0-9]+)#([0-9]+)#([0-9]+)#"
    # pattern = re.compile(r"##(.*?)##\s*([0-9]+)#([0-9]+)#([0-9]+)#")

    matches = re.findall(pattern, text, re.DOTALL)
    questionslist.clear()
    for match in matches:
        q, m, d, c = match
        # Validate difficulty level (should be 1, 2, or 3)
        difficulty = int(d)
        if difficulty not in {1, 2, 3}:
            print(f"Warning: Question has invalid difficulty level {difficulty}, skipping: {q[:50]}...")
            continue
        questionslist.append([q.strip(), int(m), difficulty, int(c)])


'''def processfile():
    global questionslist
    with open(filename, 'r', encoding='utf-8') as file:
        text = file.read()
    pattern = r"##(.*?)##\s*([0-9]+)#([0-9]+)#([0-9]+)#"
    matches = re.findall(pattern, text, re.DOTALL)
    questionslist.clear()
    for match in matches:
        q, m, d, c = match
        questionslist.append([q.strip(), int(m), int(d), int(c)])'''


def select_questions():
    question_count = get_question_count()
    if not question_count:  # User cancelled
        return []

    # Filter out any questions with invalid difficulty levels (not 1, 2, or 3)
    valid_questions = [q for q in questionslist if q[2] in {1, 2, 3}]
    if not valid_questions:
        messagebox.showerror("Error", "No valid questions found (all have invalid difficulty levels)")
        return []

    co_dict = defaultdict(list)
    for q in valid_questions:
        co_dict[q[3]].append(q)

    selected_questions = []
    co_selected = {}

    # Calculate questions per CO (distribute evenly)
    co_count = len(co_dict)
    if co_count == 0:
        return []

    base_per_co = question_count // co_count
    extra = question_count % co_count

    # Step 1: Distribute questions across COs
    for co_level in sorted(co_dict.keys()):
        questions = co_dict[co_level]
        if len(questions) < 1:
            continue

        # Determine how many to take from this CO
        take = base_per_co
        if extra > 0:
            take += 1
            extra -= 1

        # Weight for selection: favor Medium difficulty
        weights = []
        for q in questions:
            weights.append(3 if q[2] == 2 else 1)

        if len(questions) < take:
            take = len(questions)

        try:
            indices = np.random.choice(range(len(questions)), size=take, replace=False,
                                       p=np.array(weights) / sum(weights))
            selected = [questions[i] for i in indices]
            selected_questions.extend(selected)
            co_selected[co_level] = selected
        except ValueError as e:
            messagebox.showerror("Error", f"Could not select questions for CO {co_level}: {str(e)}")
            continue

    # Count current difficulty
    def count_difficulty(questions):
        return {
            1: [q for q in questions if q[2] == 1],  # Easy
            2: [q for q in questions if q[2] == 2],  # Medium
            3: [q for q in questions if q[2] == 3],  # Hard
        }

    difficulty = count_difficulty(selected_questions)

    # Step 2: Ensure reasonable difficulty distribution (20% easy, 60% medium, 20% hard)
    target_easy = max(1, round(question_count * 0.2))
    target_hard = max(1, round(question_count * 0.2))

    def try_replace(difficulty_type, target_count):
        current_count = len(difficulty.get(difficulty_type, []))
        needed = target_count - current_count
        if needed <= 0:
            return

        for co_level in co_selected:
            co_qs = co_selected[co_level]
            for i, q in enumerate(co_qs):
                if q[2] != difficulty_type and q[2] in {1, 2, 3}:  # Not already our target type and valid
                    pool = [qq for qq in co_dict[co_level]
                            if qq[2] == difficulty_type
                            and qq not in selected_questions]
                    if pool:
                        replacement = random.choice(pool)
                        original = co_selected[co_level][i]
                        selected_questions[selected_questions.index(original)] = replacement
                        co_selected[co_level][i] = replacement
                        if difficulty_type not in difficulty:
                            difficulty[difficulty_type] = []
                        difficulty[difficulty_type].append(replacement)
                        if q[2] in difficulty:
                            difficulty[q[2]].remove(original)
                        needed -= 1
                        if needed == 0:
                            return

    try_replace(1, target_easy)  # Ensure enough Easy
    try_replace(3, target_hard)  # Ensure enough Hard

    return selected_questions

def generate_pdf(questions, filepath, key, pdf_password):
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    logo_path = "about_logo.png"
    if os.path.exists(logo_path):
        elements.append(Image(logo_path, width=100, height=100))

    dt = datetime.datetime.now()
    elements += [
        Paragraph("<b>Rajkiya Engineering College Banda</b>", styles["Title"]),
        Paragraph(f"Date: {dt.strftime('%d/%m/%Y')} | Time: {dt.strftime('%H:%M:%S')}", styles["Normal"]),
        Paragraph(f"Total Questions: {len(questions)}", styles["Normal"]),
        Paragraph("<br/>", styles["Normal"])
    ]
    table_data = []
    diff_count = {"Easy": 0, "Medium": 0, "Hard": 0}
    for i, q in enumerate(questions):
        level = ['Easy', 'Medium', 'Hard'][q[2] - 1]
        diff_count[level] += 1
        table_data.append([
            Paragraph(f"{i + 1}. {escape(q[0])}", styles["Normal"]),
            Paragraph("Marks: 10", styles["Normal"]),
            Paragraph(level, styles["Normal"]),
            Paragraph(f"CO: {q[3]}", styles["Normal"])
        ])

    table = Table(table_data, colWidths=[300, 50, 80, 50])
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 1, colors.black)]))
    elements.append(table)

    plt.bar(diff_count.keys(), diff_count.values(), color=['green', 'blue', 'red'])
    plt.savefig("difficulty_graph.png")
    plt.close()
    elements.append(Paragraph("Difficulty Level Distribution:", styles["Heading2"]))
    elements.append(Image("difficulty_graph.png", width=400, height=300))

    doc.build(elements)

    # 🔐 Add password protection
    protected_path = add_password_to_pdf(filepath, pdf_password)

    # 🔒 Encrypt the password-protected PDF
    with open(protected_path, 'rb') as f:
        encrypted = fernet.encrypt(f.read())

    with open(filepath + ".enc", 'wb') as f:
        f.write(encrypted)

    os.remove(filepath)
    os.remove(protected_path)  # Clean up intermediate protected file

    messagebox.showinfo("Success", f"Encrypted & Password-Protected Paper Saved as:\n{filepath}.enc")


def generate_encrypted_paper():
    global fernet

    status_label_gen.config(text="⏳ Processing questions...", bootstyle="warning")
    processfile()

    questions = select_questions()
    if not questions:
        status_label_gen.config(text="🚫 No questions selected", bootstyle="danger")
        return

    out_dir = filedialog.askdirectory()
    if not out_dir:
        return

    # Generate a fresh encryption key for this paper
    encryption_key = Fernet.generate_key()
    fernet = Fernet(encryption_key)

    filepath = os.path.join(out_dir, "Question_Paper.pdf")

    # Save encryption key
    key_filepath = os.path.join(out_dir, "encryption_key.key")
    with open(key_filepath, 'wb') as keyfile:
        keyfile.write(encryption_key)

    # Generate and encrypt PDF
    pdf_password = simpledialog.askstring("PDF Password",
                                          "Enter a password to protect the PDF:",
                                          show='*')
    if not pdf_password:
        messagebox.showwarning("No Password", "No password entered. PDF will not be generated.")
        return

    generate_pdf(questions, filepath, encryption_key, pdf_password)

    messagebox.showinfo("Key Saved", f"Encryption key saved at:\n{key_filepath}")
    status_label_gen.config(text=f"✅ Paper Generated with {len(questions)} questions!", bootstyle="success")



from PyPDF2 import PdfReader, PdfWriter

def add_password_to_pdf(pdf_path, password):
    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(user_password=password, owner_password=None, use_128bit=True)

    protected_path = pdf_path.replace(".pdf", "_protected.pdf")
    with open(protected_path, "wb") as f:
        writer.write(f)

    return protected_path

def decrypt_paper():
    enc = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if not enc:
        return

    keyfile = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
    if not keyfile:
        return

    with open(keyfile, 'rb') as kf:
        key = kf.read()

    try:
        fernet_dec = Fernet(key)
        with open(enc, 'rb') as ef:
            data = fernet_dec.decrypt(ef.read())
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Invalid key or corrupted file.\n\n{str(e)}")
        return

    # Save decrypted (still password-protected) PDF
    temp_pdf = enc.replace(".enc", "_protected.pdf")
    with open(temp_pdf, 'wb') as tf:
        tf.write(data)

    # Ask for password to unlock the protected PDF
    password = simpledialog.askstring("Enter PDF Password", "Enter the PDF password:", show='*')
    if not password:
        messagebox.showwarning("No Password", "No password entered. Cannot unlock PDF.")
        return

    try:
        reader = PdfReader(temp_pdf)
        if reader.is_encrypted:
            reader.decrypt(password)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        # Save final unlocked PDF
        final_path = enc.replace(".enc", "_decrypted.pdf")
        with open(final_path, 'wb') as f:
            writer.write(f)

        os.remove(temp_pdf)
        messagebox.showinfo("Success", f"Decrypted and unlocked PDF saved to:\n{final_path}")

    except Exception as e:
        messagebox.showerror("PDF Unlock Failed", f"Incorrect password or file error:\n\n{str(e)}")
        return


ttk.Button(gen_frame, text="📂 Select Questions File", command=filechooser).pack(pady=5)
ttk.Button(gen_frame, text="📂 Select CO File", command=cofilechooser).pack(pady=5)
ttk.Button(gen_frame, text="✅ Generate & Encrypt Paper", bootstyle="success", command=generate_encrypted_paper).pack(pady=5)
ttk.Button(gen_frame, text="🔓 Decrypt Paper", bootstyle="danger", command=decrypt_paper).pack(pady=5)

# ======================== MD5 and SHA256 Tabs ========================
def hash_tab(title, algo):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=title)

    def generate_hash(file_path):
        h = hashlib.md5() if algo == 'md5' else hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096): h.update(chunk)
        return h.hexdigest()

    def encrypt():
        file = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if not file: return
        out = file.replace(".pdf", "_encrypted.pdf")
        hash_out = file.replace(".pdf", "_hash.txt")
        with open(file, 'rb') as f:
            pdf_data = f.read()
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
        enc_data = cipher.encrypt(pad(pdf_data, AES.block_size))
        with open(out, 'wb') as f:
            f.write(IV + enc_data)
        with open(hash_out, 'w') as f:
            f.write(generate_hash(file))
        messagebox.showinfo("Success", f"Encrypted: {out}\nHash: {hash_out}")

    def decrypt():
        file = filedialog.askopenfilename(filetypes=[("Encrypted PDF", "*_encrypted.pdf")])
        if not file:
            return
        hash_file = filedialog.askopenfilename(filetypes=[("Hash File", "*_hash.txt")])
        if not hash_file:
            return

        # Read original hash
        with open(hash_file, 'r') as hf:
            original_hash = hf.read().strip()

        # Decrypt the file
        with open(file, 'rb') as f:
            data = f.read()
        try:
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, data[:16])
            dec = unpad(cipher.decrypt(data[16:]), AES.block_size)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed: " + str(e))
            return

        # Generate hash of decrypted content
        h = hashlib.md5() if algo == 'md5' else hashlib.sha256()
        h.update(dec)
        decrypted_hash = h.hexdigest()

        out_path = file.replace("_encrypted.pdf", "_decrypted.pdf")

        if decrypted_hash == original_hash:
            with open(out_path, 'wb') as df:
                df.write(dec)
            messagebox.showinfo("Success", f"PDF decrypted successfully at:\n{out_path}")
        else:
            # Create alert PDF
            alert_path = file.replace("_encrypted.pdf", "_ALERT.pdf")
            doc = SimpleDocTemplate(alert_path, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = [Paragraph("<b>⚠ ALERT: File has been tampered!</b>", styles["Title"]),
                        Paragraph("The integrity of this file cannot be verified.", styles["Normal"])]
            doc.build(elements)
            messagebox.showwarning("Modified File", f"Tampering detected! Alert PDF saved at:\n{alert_path}")



    def verify():
        file = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        hashf = filedialog.askopenfilename(filetypes=[("Hash File", "*_hash.txt")])
        if not file or not hashf: return
        with open(hashf, 'r') as f:
            saved_hash = f.read().strip()
        current = generate_hash(file)
        msg = "Authentic" if current == saved_hash else "Modified! Alert!"
        messagebox.showinfo("Verification", msg)

    ttk.Button(frame, text="Encrypt & Hash", bootstyle="success", command=encrypt).pack(pady=5)
    ttk.Button(frame, text="Decrypt PDF", bootstyle="info", command=decrypt).pack(pady=5)
    ttk.Button(frame, text="Verify Integrity", bootstyle="warning", command=verify).pack(pady=5)

hash_tab("🔐 MD5 Security", "md5")
hash_tab("🔐 SHA-256 Security", "sha256")

root.mainloop()
