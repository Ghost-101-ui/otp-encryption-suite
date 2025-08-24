import os
import re
import base64
import hashlib
import secrets
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, scrolledtext

# ====== CONFIG ======
BASE_DIR = r"C:\D disk\OTP_V1\OTP_Encryption_Project"
DIRS = {
    "encrypted": os.path.join(BASE_DIR, "encrypted"),
    "decrypted": os.path.join(BASE_DIR, "decrypted"),
    "keys":      os.path.join(BASE_DIR, "keys"),
    "tests":     os.path.join(BASE_DIR, "test_files"),
    "log":       os.path.join(BASE_DIR, "log"),
}
BASE_NAMES = {
    "enc": "encrypted_data",
    "dec": "decrypted",
    "key_raw": "key_raw",
    "key_hash": "key_hash",
}
LOG_FILE = os.path.join(DIRS["log"], "activity_log.txt")
for d in DIRS.values():
    os.makedirs(d, exist_ok=True)

# ====== CRYPTO HELPERS ======
def log(action: str, details: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action}: {details}\n")

def next_index(folder: str, base_name: str, ext: str = "txt") -> int:
    pattern = re.compile(rf"^{re.escape(base_name)}(\d*)\.{re.escape(ext)}$")
    max_i = -1
    for fn in os.listdir(folder):
        m = pattern.match(fn)
        if m:
            suf = m.group(1)
            i = int(suf) if suf else 0
            if i > max_i:
                max_i = i
    return max_i + 1

def build_name(folder: str, base_name: str, index: int, ext: str = "txt") -> str:
    name = f"{base_name}.{ext}" if index == 0 else f"{base_name}{index}.{ext}"
    return os.path.join(folder, name)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) != len(key):
        raise ValueError(f"Key length ({len(key)}) must match data length ({len(data)}).")
    return bytes([b ^ k for b, k in zip(data, key)])

def generate_key_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)

def save_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
def save_text(path: str, text: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

# ====== GUI HACKER THEME CONSTANTS ======
class HackerStyle:
    BG = "#101417"
    FG = "#09ff3c"
    FG_ALT = "#00d9ff"
    FG_ERR = "#ff3659"
    FG_WARN = "#ffd400"
    FONT = ("Consolas", 12)
    FONT_BANNER = ("Consolas", 16, "bold")
    ENTRY_BG = "#16191d"
    ENTRY_FG = "#09ff3c"

# ====== MAIN APP ======
class OTPGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OTP Encryption Suite")
        self.geometry("770x480")
        self.configure(bg=HackerStyle.BG)
        self.active_frame = None
        self.banner_frame = tk.Frame(self, bg=HackerStyle.BG)
        self.banner_frame.pack(side=tk.TOP, fill=tk.X)
        self.show_banner()
        self.show_main_menu()

    def add_hover_glow_text_only(self, button):
        """Bind hover to glow text only (no background change)"""
        normal_fg = button.cget("fg")
        glow_fg = "#0fff60"  # bright neon green glow color
        def on_enter(e):
            button.config(fg=glow_fg)
        def on_leave(e):
            button.config(fg=normal_fg)
        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

    def show_banner(self):
        for widget in self.banner_frame.winfo_children():
            widget.destroy()
        banner = (
            "╔═══════════════════════════════════════════════════════════════╗\n"
            "║   ██████╗ ████████╗ ██████╗                                   ║\n"
            "║   ██╔═══██╗╚══██╔══╝ ██╔══██╗                                 ║\n"
            "║   ██║   ██║   ██║    ██████╔╝  OTP ENCRYPTION SUITE           ║\n"
            "║   ██║   ██║   ██║    ██╔═══╝   SECURE • FAST • HACKER MODE    ║\n"
            "║   ╚██████╔╝   ██║    ██║                                      ║\n"
            "║    ╚═════╝    ╚═╝    ╚═╝                                      ║\n"
            "╚═══════════════════════════════════════════════════════════════╝"
        )
        label = tk.Label(self.banner_frame, text=banner, fg=HackerStyle.FG_ALT,
                         bg=HackerStyle.BG, font=HackerStyle.FONT_BANNER, justify="left")
        label.pack(pady=6)

    def clear_active_frame(self):
        if self.active_frame:
            self.active_frame.destroy()
            self.active_frame = None

    def show_main_menu(self):
        self.clear_active_frame()
        self.active_frame = tk.Frame(self, bg=HackerStyle.BG)
        self.active_frame.pack(fill=tk.BOTH, expand=1)
        btn_opts = dict(bg=HackerStyle.BG, fg=HackerStyle.FG, font=("Consolas", 15), width=18, height=2, relief=tk.FLAT)
        tk.Label(self.active_frame, text="", bg=HackerStyle.BG).pack(pady=25)

        btn_encrypt = tk.Button(self.active_frame, text="🔐 Encrypt", command=self.show_encrypt_page, **btn_opts)
        btn_encrypt.pack(pady=12)
        self.add_hover_glow_text_only(btn_encrypt)

        btn_decrypt = tk.Button(self.active_frame, text="🔓 Decrypt", command=self.show_decrypt_page, **btn_opts)
        btn_decrypt.pack(pady=12)
        self.add_hover_glow_text_only(btn_decrypt)

        btn_exit = tk.Button(self.active_frame, text="🚪 Exit", command=self.destroy, **btn_opts)
        btn_exit.pack(pady=12)
        self.add_hover_glow_text_only(btn_exit)

    def show_encrypt_page(self):
        self.clear_active_frame()
        self.active_frame = tk.Frame(self, bg=HackerStyle.BG)
        self.active_frame.pack(fill=tk.BOTH, expand=1)
        self.show_banner()
        tk.Label(self.active_frame, text="", bg=HackerStyle.BG).pack(pady=4)
        tk.Label(self.active_frame, text="Enter plaintext OR select file:", fg=HackerStyle.FG, bg=HackerStyle.BG, font=HackerStyle.FONT).pack()
        self.plain_entry = tk.Entry(self.active_frame, bg=HackerStyle.ENTRY_BG, fg=HackerStyle.ENTRY_FG,
                                    font=HackerStyle.FONT, insertbackground=HackerStyle.FG, width=60)
        self.plain_entry.pack(pady=4)
        btn_browse = tk.Button(self.active_frame, text="Browse File", command=self.browse_plain_file,
                               bg=HackerStyle.BG, fg=HackerStyle.FG, font=HackerStyle.FONT, relief=tk.FLAT)
        btn_browse.pack()
        self.add_hover_glow_text_only(btn_browse)

        tk.Label(self.active_frame, text="Key Generation:", fg=HackerStyle.FG, bg=HackerStyle.BG, font=HackerStyle.FONT).pack(pady=6)
        self.key_var = tk.StringVar(value="auto")
        rb_frame = tk.Frame(self.active_frame, bg=HackerStyle.BG)
        rb_frame.pack()
        tk.Radiobutton(rb_frame, text="Auto", variable=self.key_var, value="auto", fg=HackerStyle.FG,
                       bg=HackerStyle.BG, font=HackerStyle.FONT, selectcolor=HackerStyle.BG,
                       command=self.toggle_manual_key_entry).pack(side="left", padx=18)
        tk.Radiobutton(rb_frame, text="Manual", variable=self.key_var, value="manual", fg=HackerStyle.FG,
                       bg=HackerStyle.BG, font=HackerStyle.FONT, selectcolor=HackerStyle.BG,
                       command=self.toggle_manual_key_entry).pack(side="left", padx=18)
        self.manual_key_label = tk.Label(self.active_frame, text="Manual key (same byte length as plaintext):",
                                         fg=HackerStyle.FG, bg=HackerStyle.BG, font=HackerStyle.FONT)
        self.manual_key_entry = tk.Entry(self.active_frame, bg=HackerStyle.ENTRY_BG, fg=HackerStyle.ENTRY_FG,
                                         font=HackerStyle.FONT, insertbackground=HackerStyle.FG, width=60)
        self.manual_key_label.pack_forget()
        self.manual_key_entry.pack_forget()

        btn_encrypt = tk.Button(self.active_frame, text="Encrypt", command=self.encrypt_action,
                                bg=HackerStyle.BG, fg=HackerStyle.FG_WARN, font=HackerStyle.FONT, relief=tk.FLAT)
        btn_encrypt.pack(pady=12)
        self.add_hover_glow_text_only(btn_encrypt)

        btn_back = tk.Button(self.active_frame, text="Back", command=self.show_main_menu,
                             bg=HackerStyle.BG, fg=HackerStyle.FG, font=HackerStyle.FONT, relief=tk.FLAT)
        btn_back.pack()
        self.add_hover_glow_text_only(btn_back)

        self.terminal = scrolledtext.ScrolledText(self.active_frame, height=12,
                                                  bg="#000d09", fg="#09ff3c", insertbackground="#0fff60",
                                                  font=("Consolas", 14), relief=tk.RIDGE,
                                                  bd=5)
        self.terminal.pack(fill=tk.BOTH, expand=1, padx=12, pady=8)

    def toggle_manual_key_entry(self):
        if self.key_var.get() == "manual":
            self.manual_key_label.pack()
            self.manual_key_entry.pack()
        else:
            self.manual_key_label.pack_forget()
            self.manual_key_entry.pack_forget()

    def browse_plain_file(self):
        file = filedialog.askopenfilename(initialdir=DIRS["tests"], title="Select File")
        if file:
            self.plain_entry.delete(0, tk.END)
            self.plain_entry.insert(0, file)

    def encrypt_action(self):
        self.terminal.delete("1.0", tk.END)
        src = self.plain_entry.get().strip()
        if os.path.isfile(src):
            with open(src, "rb") as f:
                plaintext = f.read()
        else:
            plaintext = src.encode("utf-8")
        if len(plaintext) == 0:
            self.terminal.insert(tk.END, "ERROR: Plaintext is empty!\n")
            return
        key_mode = self.key_var.get()
        if key_mode == "auto":
            key = generate_key_bytes(len(plaintext))
            status_key = f"Auto-generated key ({len(key)} bytes).\n"
        else:
            key_str = self.manual_key_entry.get()
            key = key_str.encode("utf-8")
            if len(key) != len(plaintext):
                self.terminal.insert(tk.END, f"ERROR: Manual key length mismatch! Must be {len(plaintext)} bytes.\n")
                return
            status_key = "Manual key provided.\n"
        try:
            ciphertext_bytes = xor_bytes(plaintext, key)
        except Exception as ex:
            self.terminal.insert(tk.END, f"ERROR: {str(ex)}\n")
            return
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")
        key_hash = sha256_hex(key)
        idx = next_index(DIRS["encrypted"], BASE_NAMES["enc"], "txt")
        enc_path  = build_name(DIRS["encrypted"], BASE_NAMES["enc"], idx, "txt")
        rawk_path = build_name(DIRS["keys"],     BASE_NAMES["key_raw"], idx, "bin")
        hash_path = build_name(DIRS["keys"],     BASE_NAMES["key_hash"], idx, "txt")
        save_text(enc_path, ciphertext_b64)
        save_bytes(rawk_path, key)
        save_text(hash_path, key_hash)
        log("Encryption", f"enc={os.path.basename(enc_path)} | key_raw={os.path.basename(rawk_path)} | key_hash={os.path.basename(hash_path)} | plaintext_bytes={len(plaintext)}")
        log("Key Generated", f"bytes={len(key)} | hash={key_hash}")
        self.terminal.insert(tk.END,
            f"✔ ENCRYPTION SUCCESS!\nEncrypted file: {enc_path}\nRAW Key file: {rawk_path}\nKey Hash file: {hash_path}\n"
            f"{status_key}SECURITY: Keep RAW key SAFE!\n"
        )
        self.terminal.see(tk.END)

    def show_decrypt_page(self):
        self.clear_active_frame()
        self.active_frame = tk.Frame(self, bg=HackerStyle.BG)
        self.active_frame.pack(fill=tk.BOTH, expand=1)
        self.show_banner()
        tk.Label(self.active_frame, text="", bg=HackerStyle.BG).pack(pady=4)
        tk.Label(self.active_frame, text="Enter encrypted file (Base64 or path):", fg=HackerStyle.FG, bg=HackerStyle.BG, font=HackerStyle.FONT).pack()
        self.enc_file_entry = tk.Entry(self.active_frame, bg=HackerStyle.ENTRY_BG, fg=HackerStyle.ENTRY_FG,
                                      font=HackerStyle.FONT, insertbackground=HackerStyle.FG, width=60)
        self.enc_file_entry.pack(pady=4)
        btn_browse = tk.Button(self.active_frame, text="Browse File", command=self.browse_enc_file,
                               bg=HackerStyle.BG, fg=HackerStyle.FG, font=HackerStyle.FONT, relief=tk.FLAT)
        btn_browse.pack()
        self.add_hover_glow_text_only(btn_browse)

        tk.Label(self.active_frame, text="Decryption mode:", fg=HackerStyle.FG, bg=HackerStyle.BG, font=HackerStyle.FONT).pack(pady=6)
        self.dec_mode = tk.StringVar(value="auto")
        rb_frame = tk.Frame(self.active_frame, bg=HackerStyle.BG)
        rb_frame.pack()
        tk.Radiobutton(rb_frame, text="Auto", variable=self.dec_mode, value="auto", fg=HackerStyle.FG,
                       bg=HackerStyle.BG, font=HackerStyle.FONT, selectcolor=HackerStyle.BG,
                       command=self.toggle_manual_dec_entries).pack(side="left", padx=18)
        tk.Radiobutton(rb_frame, text="Manual", variable=self.dec_mode, value="manual", fg=HackerStyle.FG,
                       bg=HackerStyle.BG, font=HackerStyle.FONT, selectcolor=HackerStyle.BG,
                       command=self.toggle_manual_dec_entries).pack(side="left", padx=18)

        self.manual_dec_key_label = tk.Label(self.active_frame, text="Manual key (same length as ciphertext):", fg=HackerStyle.FG, bg=HackerStyle.BG, font=HackerStyle.FONT)
        self.manual_dec_key_entry = tk.Entry(self.active_frame, bg=HackerStyle.ENTRY_BG, fg=HackerStyle.ENTRY_FG,
                                            font=HackerStyle.FONT, insertbackground=HackerStyle.FG, width=60)
        self.hash_file_label = tk.Label(self.active_frame, text="Hash file (key_hash*.txt):", fg=HackerStyle.FG, bg=HackerStyle.BG, font=HackerStyle.FONT)
        self.hash_file_entry = tk.Entry(self.active_frame, bg=HackerStyle.ENTRY_BG, fg=HackerStyle.ENTRY_FG,
                                       font=HackerStyle.FONT, insertbackground=HackerStyle.FG, width=60)
        self.btn_hash_browse = tk.Button(self.active_frame, text="Browse Hash File", command=self.browse_hash_file,
                                    bg=HackerStyle.BG, fg=HackerStyle.FG, font=HackerStyle.FONT, relief=tk.FLAT)

        self.manual_dec_key_label.pack_forget()
        self.manual_dec_key_entry.pack_forget()
        self.hash_file_label.pack_forget()
        self.hash_file_entry.pack_forget()
        self.btn_hash_browse.pack_forget()

        btn_decrypt = tk.Button(self.active_frame, text="Decrypt", command=self.decrypt_action,
                                bg=HackerStyle.BG, fg=HackerStyle.FG_WARN, font=HackerStyle.FONT, relief=tk.FLAT)
        btn_decrypt.pack(pady=12)
        self.add_hover_glow_text_only(btn_decrypt)

        btn_back = tk.Button(self.active_frame, text="Back", command=self.show_main_menu,
                             bg=HackerStyle.BG, fg=HackerStyle.FG, font=HackerStyle.FONT, relief=tk.FLAT)
        btn_back.pack()
        self.add_hover_glow_text_only(btn_back)

        self.terminal = scrolledtext.ScrolledText(self.active_frame, height=12,
                                                  bg="#000d09", fg="#09ff3c", insertbackground="#0fff60",
                                                  font=("Consolas", 14), relief=tk.RIDGE,
                                                  bd=5)
        self.terminal.pack(fill=tk.BOTH, expand=1, padx=12, pady=8)

    def toggle_manual_dec_entries(self):
        if self.dec_mode.get() == "manual":
            self.manual_dec_key_label.pack()
            self.manual_dec_key_entry.pack()
            self.hash_file_label.pack()
            self.hash_file_entry.pack()
            self.btn_hash_browse.pack()
        else:
            self.manual_dec_key_label.pack_forget()
            self.manual_dec_key_entry.pack_forget()
            self.hash_file_label.pack_forget()
            self.hash_file_entry.pack_forget()
            self.btn_hash_browse.pack_forget()

    def browse_enc_file(self):
        file = filedialog.askopenfilename(initialdir=DIRS["encrypted"], title="Select Encrypted File")
        if file:
            self.enc_file_entry.delete(0, tk.END)
            self.enc_file_entry.insert(0, file)

    def browse_hash_file(self):
        file = filedialog.askopenfilename(initialdir=DIRS["keys"], title="Select Key Hash File")
        if file:
            self.hash_file_entry.delete(0, tk.END)
            self.hash_file_entry.insert(0, file)

    def find_index_from_enc_filename(self, enc_path: str) -> int or None:
        bn = os.path.basename(enc_path)
        m = re.match(rf"^{re.escape(BASE_NAMES['enc'])}(\d*)\.txt$", bn)
        if not m:
            return None
        return int(m.group(1)) if m.group(1) else 0

    def decrypt_action(self):
        self.terminal.delete("1.0", tk.END)
        enc_path = self.enc_file_entry.get().strip()
        mode = self.dec_mode.get()
        if not os.path.isfile(enc_path):
            self.terminal.insert(tk.END, "ERROR: Encrypted file not found!\n")
            return
        with open(enc_path, "r", encoding="utf-8") as f:
            ciphertext_b64 = f.read().strip()
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        if mode == "auto":
            idx = self.find_index_from_enc_filename(enc_path)
            if idx is None:
                self.terminal.insert(tk.END, "ERROR: Invalid encrypted filename pattern for auto mode!\n")
                return
            rawk_path = build_name(DIRS["keys"], BASE_NAMES["key_raw"], idx, "bin")
            hash_path = build_name(DIRS["keys"], BASE_NAMES["key_hash"], idx, "txt")
            if not os.path.isfile(rawk_path):
                self.terminal.insert(tk.END, "ERROR: RAW key file not found!\n")
                return
            with open(rawk_path, "rb") as f:
                key = f.read()
            stored_hash = None
            if os.path.isfile(hash_path):
                with open(hash_path, "r", encoding="utf-8") as f:
                    stored_hash = f.read().strip()
            if stored_hash and sha256_hex(key) != stored_hash:
                self.terminal.insert(tk.END, "ERROR: Key hash verification failed!\n")
                return
        else:
            key_str = self.manual_dec_key_entry.get()
            key = key_str.encode("utf-8")
            if len(key) != len(ciphertext_bytes):
                self.terminal.insert(tk.END, f"ERROR: Key length mismatch! Must be {len(ciphertext_bytes)} bytes.\n")
                return
            hash_path = self.hash_file_entry.get().strip()
            if not os.path.isfile(hash_path):
                self.terminal.insert(tk.END, "ERROR: Hash file not found!\n")
                return
            with open(hash_path, "r", encoding="utf-8") as f:
                stored_hash = f.read().strip()
            if sha256_hex(key) != stored_hash:
                self.terminal.insert(tk.END, "ERROR: Key verification failed!\n")
                return
        try:
            plaintext = xor_bytes(ciphertext_bytes, key)
        except Exception as ex:
            self.terminal.insert(tk.END, f"ERROR: {str(ex)}\n")
            return
        try:
            decrypted_text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            decrypted_text = f"(Binary data)\n{plaintext.hex()}"
        idx_out = next_index(DIRS["decrypted"], BASE_NAMES["dec"], "txt")
        dec_path = build_name(DIRS["decrypted"], BASE_NAMES["dec"], idx_out, "txt")
        save_bytes(dec_path, plaintext)
        log("Decryption", f"enc={os.path.basename(enc_path)} | key_used | out={os.path.basename(dec_path)}")
        self.terminal.insert(tk.END, f"✔ DECRYPTION SUCCESS!\nDecrypted file: {dec_path}\n\n{decrypted_text}\n")
        self.terminal.see(tk.END)

if __name__ == "__main__":
    app = OTPGui()
    app.mainloop()
