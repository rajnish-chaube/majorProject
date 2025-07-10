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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from PIL import Image as PILImage
from reportlab.platypus import Image as RLImage
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
from ttkbootstrap.style import Bootstyle
from PIL import ImageTk

# AES Constants
SECRET_KEY = b"thisisrysecureky"  # 16 bytes
IV = b"thisis16bytesiv1"

# === Main Window ===
root = ttk.Window(themename="cyborg")
root.title("Secure Question Paper Generation System")
root.geometry("1200x800")
root.minsize(1000, 700)

# Custom font styles
title_font = ("Helvetica", 16, "bold")
subtitle_font = ("Helvetica", 12, "bold")
button_font = ("Helvetica", 10, "bold")
status_font = ("Helvetica", 10)

# Create style for centered buttons
style = ttk.Style()
style.configure("Centered.TButton", justify="center")

# Header Frame
header_frame = ttk.Frame(root, bootstyle="dark")
header_frame.pack(fill="x", padx=10, pady=5)

# Logo placeholder (you can replace with your actual logo)
logo_label = ttk.Label(header_frame, text="📝", font=("Arial", 24))
logo_label.pack(side="left", padx=10)

# Title
title_label = ttk.Label(
    header_frame,
    text="Secure Question Paper Generation System",
    font=title_font,
    bootstyle="inverse-light"
)
title_label.pack(side="left", padx=10, fill="x", expand=True)

# Status bar
status_bar = ttk.Label(
    root,
    text="Ready",
    bootstyle="dark",  # Changed from "info"
    anchor="center",
    font=status_font,
    relief="flat"  # More modern flat style
)
status_bar.pack(fill="x", side="bottom", padx=10, pady=5)

# Main Notebook
notebook = ttk.Notebook(root, bootstyle="light")
notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))


# ======================== Secure Paper Generator ========================
gen_frame = ttk.Frame(notebook)
notebook.add(gen_frame, text="📝 Paper Generator")

# Create a container frame with padding
container = ttk.Frame(gen_frame)
container.pack(fill="both", expand=True, padx=20, pady=20)

# Section headers
generator_header = ttk.Label(
    container,
    text="Question Paper Generator",
    font=subtitle_font,
    bootstyle="info"
)
generator_header.pack(pady=(0, 15))

# File selection frame
file_frame = ttk.LabelFrame(
    container,
    text="File Selection",
    bootstyle="info",
    padding=15
)
file_frame.pack(fill="x", pady=10)

# Button grid for file operations
button_grid = ttk.Frame(file_frame)
button_grid.pack(fill="x")

# Column configuration for even spacing
button_grid.columnconfigure(0, weight=1)
button_grid.columnconfigure(1, weight=1)
button_grid.columnconfigure(2, weight=1)

# File selection buttons
questions_file_btn = ttk.Button(
    button_grid,
    text="📂 Select Questions File",
    command=lambda: filechooser(),
    style="Centered.TButton",
    width=25,
    bootstyle="primary"
)
questions_file_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

co_file_btn = ttk.Button(
    button_grid,
    text="📂 Select CO File",
    command=lambda: cofilechooser(),
    style="Centered.TButton",
    width=25,
    bootstyle="primary"
)
co_file_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# Status indicators
file_status_frame = ttk.Frame(file_frame)
file_status_frame.pack(fill="x", pady=(5, 0))

questions_status = ttk.Label(
    file_status_frame,
    text="No questions file selected",
    bootstyle="secondary",
    font=status_font
)
questions_status.pack(side="left", padx=5)

co_status = ttk.Label(
    file_status_frame,
    text="No CO file selected",
    bootstyle="secondary",
    font=status_font
)
co_status.pack(side="left", padx=5)

# Action buttons frame
action_frame = ttk.LabelFrame(
    container,
    text="Actions",
    bootstyle="info",
    padding=15
)
action_frame.pack(fill="x", pady=10)

generate_btn = ttk.Button(
    action_frame,
    text="✅ Generate & Encrypt Paper",
    command=lambda: generate_encrypted_paper(),
    style="Centered.TButton",
    width=30,
    bootstyle="success"
)
generate_btn.pack(pady=5)

decrypt_btn = ttk.Button(
    action_frame,
    text="🔓 Decrypt Paper",
    command=lambda: decrypt_paper(),
    style="Centered.TButton",
    width=30,
    bootstyle="danger"
)
decrypt_btn.pack(pady=5)

# Progress/Status frame
progress_frame = ttk.Frame(container)
progress_frame.pack(fill="x", pady=10)

progress_bar = ttk.Progressbar(
    progress_frame,
    bootstyle="striped-info",
    mode="determinate"
)
progress_bar.pack(fill="x", pady=5)

status_label = ttk.Label(
    progress_frame,
    text="Ready to generate question papers",
    bootstyle="info",
    font=status_font,
    anchor="center"
)
status_label.pack(fill="x")

# Global variables
questionslist, filename, colist = [], "", []
encryption_key = Fernet.generate_key()
fernet = Fernet(encryption_key)


def update_status(message, style="info"):
    """Update the status label with a message and style"""
    status_label.config(text=message, bootstyle=style)
    status_bar.config(text=message, bootstyle=style)
    root.update_idletasks()


def filechooser():
    global filename
    filename = filedialog.askopenfilename(
        title="Select Questions File",
        filetypes=[("Text Files", "*.txt")]
    )
    if filename:
        questions_status.config(text=f"Selected: {os.path.basename(filename)}", bootstyle="success")
        update_status("Questions file loaded successfully", "success")


def cofilechooser():
    global colist
    cofile = filedialog.askopenfilename(
        title="Select CO File",
        filetypes=[("Text Files", "*.txt")]
    )
    if cofile:
        with open(cofile, 'r') as f:
            colist.clear()
            colist.extend([line.strip() for line in f if line.strip()])
        co_status.config(text=f"Selected: {os.path.basename(cofile)}", bootstyle="success")
        update_status("CO file loaded successfully", "success")


def get_question_count():
    return simpledialog.askinteger(
        "Question Count",
        "Enter number of questions to generate:",
        parent=root,
        minvalue=5,
        maxvalue=20
    )


def processfile():
    global questionslist
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            text = file.read()
        pattern = r"##(.*?)##\s*([0-9]+)#([0-9]+)#([0-9]+)#"
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
        update_status(f"Processed {len(questionslist)} questions", "success")
        return True
    except Exception as e:
        update_status(f"Error processing file: {str(e)}", "danger")
        return False


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
        elements.append(RLImage(logo_path, width=100, height=100))  # Changed here

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
    elements.append(RLImage("difficulty_graph.png", width=400, height=300))

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
    # Rest of the function remains the same...

def generate_encrypted_paper():
    global fernet

    if not filename:
        messagebox.showerror("Error", "Please select a questions file first")
        return

    if not colist:
        messagebox.showerror("Error", "Please select a CO file first")
        return

    update_status("Processing questions...", "warning")
    progress_bar["value"] = 20
    if not processfile():
        return

    questions = select_questions()
    if not questions:
        update_status("No questions selected", "danger")
        progress_bar["value"] = 0
        return

    out_dir = filedialog.askdirectory(title="Select Output Directory")
    if not out_dir:
        progress_bar["value"] = 0
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
    pdf_password = simpledialog.askstring(
        "PDF Password",
        "Enter a password to protect the PDF:",
        parent=root,
        show='*'
    )
    if not pdf_password:
        messagebox.showwarning("No Password", "No password entered. PDF will not be generated.")
        progress_bar["value"] = 0
        return

    progress_bar["value"] = 50
    update_status("Generating PDF...", "info")
    generate_pdf(questions, filepath, encryption_key, pdf_password)

    progress_bar["value"] = 100
    messagebox.showinfo("Key Saved", f"Encryption key saved at:\n{key_filepath}")
    update_status(f"Paper Generated with {len(questions)} questions!", "success")
    progress_bar["value"] = 0


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
    update_status("Select encrypted paper...", "info")
    enc = filedialog.askopenfilename(
        title="Select Encrypted Paper",
        filetypes=[("Encrypted Files", "*.enc")]
    )
    if not enc:
        return

    update_status("Select encryption key...", "info")
    keyfile = filedialog.askopenfilename(
        title="Select Encryption Key",
        filetypes=[("Key Files", "*.key")]
    )
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
        update_status("Decryption failed", "danger")
        return

    # Save decrypted (still password-protected) PDF
    temp_pdf = enc.replace(".enc", "_protected.pdf")
    with open(temp_pdf, 'wb') as tf:
        tf.write(data)

    # Ask for password to unlock the protected PDF
    password = simpledialog.askstring(
        "Enter PDF Password",
        "Enter the PDF password:",
        parent=root,
        show='*'
    )
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
        update_status("PDF decrypted successfully", "success")
        messagebox.showinfo("Success", f"Decrypted and unlocked PDF saved to:\n{final_path}")

    except Exception as e:
        messagebox.showerror("PDF Unlock Failed", f"Incorrect password or file error:\n\n{str(e)}")
        update_status("Decryption failed", "danger")
        return


# ======================== MD5 and SHA256 Tabs ========================
def create_hash_tab(title, algo):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=title)

    # Container frame
    container = ttk.Frame(frame)
    container.pack(fill="both", expand=True, padx=20, pady=20)

    # Tab header
    tab_header = ttk.Label(
        container,
        text=f"{algo.upper()} File Security",
        font=subtitle_font,
        bootstyle="info"
    )
    tab_header.pack(pady=(0, 15))

    # File operations frame
    file_ops_frame = ttk.LabelFrame(
        container,
        text=f"{algo.upper()} Operations",
        bootstyle="info",
        padding=15
    )
    file_ops_frame.pack(fill="x", pady=10)

    def generate_hash(file_path):
        h = hashlib.md5() if algo == 'md5' else hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.hexdigest()

    def encrypt():
        file = filedialog.askopenfilename(
            title="Select PDF to Encrypt",
            filetypes=[("PDF Files", "*.pdf")]
        )
        if not file:
            return

        update_status(f"Encrypting {os.path.basename(file)}...", "info")
        progress_bar["value"] = 30

        out = file.replace(".pdf", "_encrypted.pdf")
        hash_out = file.replace(".pdf", "_hash.txt")

        try:
            with open(file, 'rb') as f:
                pdf_data = f.read()

            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
            enc_data = cipher.encrypt(pad(pdf_data, AES.block_size))

            with open(out, 'wb') as f:
                f.write(IV + enc_data)

            with open(hash_out, 'w') as f:
                f.write(generate_hash(file))

            progress_bar["value"] = 100
            update_status(f"Encrypted: {os.path.basename(out)}", "success")
            messagebox.showinfo("Success", f"Encrypted: {out}\nHash: {hash_out}")
        except Exception as e:
            update_status(f"Encryption failed: {str(e)}", "danger")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        finally:
            progress_bar["value"] = 0

    def decrypt():
        file = filedialog.askopenfilename(
            title="Select Encrypted PDF",
            filetypes=[("Encrypted PDF", "*_encrypted.pdf")]
        )
        if not file:
            return

        update_status(f"Decrypting {os.path.basename(file)}...", "info")
        progress_bar["value"] = 20

        hash_file = filedialog.askopenfilename(
            title="Select Hash File",
            filetypes=[("Hash File", "*_hash.txt")]
        )
        if not hash_file:
            progress_bar["value"] = 0
            return

        # Read original hash
        with open(hash_file, 'r') as hf:
            original_hash = hf.read().strip()

        # Decrypt the file
        try:
            with open(file, 'rb') as f:
                data = f.read()

            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, data[:16])
            dec = unpad(cipher.decrypt(data[16:]), AES.block_size)

            progress_bar["value"] = 60

            # Generate hash of decrypted content
            h = hashlib.md5() if algo == 'md5' else hashlib.sha256()
            h.update(dec)
            decrypted_hash = h.hexdigest()

            out_path = file.replace("_encrypted.pdf", "_decrypted.pdf")

            if decrypted_hash == original_hash:
                with open(out_path, 'wb') as df:
                    df.write(dec)

                progress_bar["value"] = 100
                update_status(f"Decrypted: {os.path.basename(out_path)}", "success")
                messagebox.showinfo("Success", f"PDF decrypted successfully at:\n{out_path}")
            else:
                # Create alert PDF
                alert_path = file.replace("_encrypted.pdf", "_ALERT.pdf")
                doc = SimpleDocTemplate(alert_path, pagesize=letter)
                styles = getSampleStyleSheet()
                elements = [
                    Paragraph("<b>⚠ ALERT: File has been tampered!</b>", styles["Title"]),
                    Paragraph("The integrity of this file cannot be verified.", styles["Normal"])
                ]
                doc.build(elements)
                update_status("Tampering detected!", "danger")
                messagebox.showwarning("Modified File", f"Tampering detected! Alert PDF saved at:\n{alert_path}")
        except Exception as e:
            update_status(f"Decryption failed: {str(e)}", "danger")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        finally:
            progress_bar["value"] = 0

    def verify():
        file = filedialog.askopenfilename(
            title="Select PDF to Verify",
            filetypes=[("PDF Files", "*.pdf")]
        )
        if not file:
            return

        update_status(f"Verifying {os.path.basename(file)}...", "info")
        progress_bar["value"] = 30

        hashf = filedialog.askopenfilename(
            title="Select Hash File",
            filetypes=[("Hash File", "*_hash.txt")]
        )
        if not hashf:
            progress_bar["value"] = 0
            return

        try:
            with open(hashf, 'r') as f:
                saved_hash = f.read().strip()

            current = generate_hash(file)

            progress_bar["value"] = 100

            if current == saved_hash:
                update_status("File is authentic", "success")
                messagebox.showinfo("Verification", "✅ File is authentic and unchanged")
            else:
                update_status("File has been modified!", "danger")
                messagebox.showwarning("Verification", "⚠ File has been modified!")
        except Exception as e:
            update_status(f"Verification failed: {str(e)}", "danger")
            messagebox.showerror("Error", f"Verification failed: {str(e)}")
        finally:
            progress_bar["value"] = 0

    # Buttons in a grid for better layout
    button_grid = ttk.Frame(file_ops_frame)
    button_grid.pack(fill="x")

    # Configure columns for even spacing
    button_grid.columnconfigure(0, weight=1)
    button_grid.columnconfigure(1, weight=1)
    button_grid.columnconfigure(2, weight=1)

    encrypt_btn = ttk.Button(
        button_grid,
        text="Encrypt & Hash",
        command=encrypt,
        style="Centered.TButton",
        width=20,
        bootstyle="success"
    )
    encrypt_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

    decrypt_btn = ttk.Button(
        button_grid,
        text="Decrypt PDF",
        command=decrypt,
        style="Centered.TButton",
        width=20,
        bootstyle="info"
    )
    decrypt_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    verify_btn = ttk.Button(
        button_grid,
        text="Verify Integrity",
        command=verify,
        style="Centered.TButton",
        width=20,
        bootstyle="warning"
    )
    verify_btn.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

    # Info label
    info_label = ttk.Label(
        file_ops_frame,
        text=f"Using {algo.upper()} for file integrity verification",
        bootstyle="secondary",
        font=status_font
    )
    info_label.pack(pady=(10, 0))


# Create the hash tabs
create_hash_tab("🔐 MD5 Security", "md5")
create_hash_tab("🔐 SHA-256 Security", "sha256")

# Center the window on screen
root.eval('tk::PlaceWindow . center')

root.mainloop()