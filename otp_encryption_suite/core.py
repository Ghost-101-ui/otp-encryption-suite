import os
import re
import base64
import hashlib
import secrets
import time
from datetime import datetime

# ANSI color codes for terminal styling
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    # Dark theme colors
    DARK_GRAY = '\033[90m'
    DARK_BLUE = '\033[34m'
    DARK_GREEN = '\033[32m'
    DARK_RED = '\033[31m'

# ====== CONFIG ======
# Use current working directory instead of hardcoded path
BASE_DIR = os.getcwd()
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

# ====== INITIAL SETUP ======
for d in DIRS.values():
    os.makedirs(d, exist_ok=True)

def log(action: str, details: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action}: {details}\n")

# ====== HACKER STYLING UTILITIES ======
def print_banner():
    """Display the main banner with hacker aesthetic"""
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                        ██████╗ ████████╗ ██████╗                             ║")
    print("║                       ██╔═══██╗╚══██╔══╝ ██╔══██╗                            ║")
    print("║                       ██║   ██║   ██║    ██████╔╝                            ║")
    print("║                       ██║   ██║   ██║    ██╔═══╝                             ║")
    print("║                       ╚██████╔╝   ██║    ██║                                 ║")
    print("║                        ╚═════╝    ╚═╝    ╚═╝                                 ║")
    print("║                                                                              ║")
    print("║                    ╔══════════════════════════════════════════╗              ║")
    print("║                    ║         OTP ENCRYPTION SUITE             ║              ║")
    print("║                    ║         [SECURE • FAST • RELIABLE]       ║              ║")
    print("║                    ╚══════════════════════════════════════════╝              ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}")

def print_status(message: str, status_type: str = "INFO"):
    """Print status messages with colors and formatting"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    if status_type == "SUCCESS":
        print(f"{Colors.GREEN}[✓] {timestamp} {message}{Colors.END}")
    elif status_type == "ERROR":
        print(f"{Colors.RED}[✗] {timestamp} {message}{Colors.END}")
    elif status_type == "WARNING":
        print(f"{Colors.YELLOW}[!] {timestamp} {message}{Colors.END}")
    elif status_type == "INFO":
        print(f"{Colors.CYAN}[i] {timestamp} {message}{Colors.END}")
    else:
        print(f"{Colors.DARK_GRAY}[*] {timestamp} {message}{Colors.END}")

def print_section_header(title: str):
    """Print section headers with cool styling"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{Colors.END}")

def print_progress_bar(current: int, total: int, width: int = 50):
    """Display a cool progress bar"""
    progress = int(width * current / total)
    bar = f"{Colors.DARK_GREEN}{'█' * progress}{Colors.DARK_GRAY}{'░' * (width - progress)}{Colors.END}"
    percentage = current / total * 100
    print(f"\r{Colors.CYAN}[{bar}] {percentage:.1f}%{Colors.END}", end="", flush=True)
    if current == total:
        print()

def loading_animation(duration: float = 2.0):
    """Show a loading animation"""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    start_time = time.time()
    i = 0
    while time.time() - start_time < duration:
        print(f"\r{Colors.CYAN}[{chars[i % len(chars)]}] Processing...{Colors.END}", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r{Colors.GREEN}[✓] Complete!{' ' * 20}{Colors.END}")

# ====== FILE NAMING (auto-increment) ======
def next_index(folder: str, base_name: str, ext: str = "txt") -> int:
    """
    Find the next numeric suffix for files like:
      base.txt, base1.txt, base2.txt, ...
    """
    pattern = re.compile(rf"^{re.escape(base_name)}(\d*)\.{re.escape(ext)}$")
    max_i = -1
    for fn in os.listdir(folder):
        m = pattern.match(fn)
        if m:
            suf = m.group(1)
            i = int(suf) if suf else 0
            if i > max_i:
                max_i = i
    return max_i + 1  # next available index

def build_name(folder: str, base_name: str, index: int, ext: str = "txt") -> str:
    name = f"{base_name}.{ext}" if index == 0 else f"{base_name}{index}.{ext}"
    return os.path.join(folder, name)

# ====== CRYPTO HELPERS ======
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def xor_bytes(data: bytes, key: bytes) -> bytes:
    # OTP requires same length
    if len(data) != len(key):
        raise ValueError(f"Key length ({len(key)}) must match data length ({len(data)}).")
    return bytes([b ^ k for b, k in zip(data, key)])

def generate_key_bytes(length: int) -> bytes:
    # Key over full byte range (true OTP) – but keep it printable-safe by Base64 for storage if needed
    return secrets.token_bytes(length)

# ====== IO UTILS ======
def read_text_or_file(prompt: str) -> bytes:
    """Ask user for text or a file path. If path exists, read file bytes. Else, treat input as text (UTF-8)."""
    s = input(prompt).strip('"').strip()
    if os.path.isfile(s):
        with open(s, "rb") as f:
            return f.read()
    return s.encode("utf-8")

def save_bytes(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

def save_text(path: str, text: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

# ====== ENCRYPT ======
def encrypt_flow():
    print_section_header("🔐 ENCRYPTION MODULE")
    print_status("Initializing encryption protocol...", "INFO")
    
    # 1) Read plaintext (text or file)
    print(f"\n{Colors.YELLOW}Step 1: Input Selection{Colors.END}")
    plaintext = read_text_or_file(f"{Colors.CYAN}Enter plaintext OR path to file (test_files allowed): {Colors.END}")
    if len(plaintext) == 0:
        print_status("Empty plaintext detected. Aborting operation.", "ERROR")
        return

    # 2) Key method
    print(f"\n{Colors.YELLOW}Step 2: Key Generation Strategy{Colors.END}")
    print(f"{Colors.CYAN}Key generation method?{Colors.END}")
    print(f"  {Colors.GREEN}1){Colors.END} Auto-generate (Cryptographically Secure)")
    print(f"  {Colors.GREEN}2){Colors.END} Manual (User-defined)")
    kmode = input(f"{Colors.YELLOW}Select (1/2): {Colors.END}").strip()
    
    if kmode == "1":
        print_status("Generating cryptographically secure key...", "INFO")
        loading_animation(1.5)
        key = generate_key_bytes(len(plaintext))
        print_status(f"Auto-generated key of {len(key)} bytes", "SUCCESS")
    elif kmode == "2":
        print_status(f"Manual key mode selected. Plaintext length: {len(plaintext)} bytes", "INFO")
        key_str = input(f"{Colors.CYAN}Enter your key EXACTLY this many characters: {Colors.END}")
        key = key_str.encode("utf-8")
        if len(key) != len(plaintext):
            print_status("Key length mismatch detected. Aborting operation.", "ERROR")
            return
        print_status("Manual key validation successful", "SUCCESS")
    else:
        print_status("Invalid selection detected. Aborting operation.", "ERROR")
        return

    # 3) XOR encrypt (bytes)
    print(f"\n{Colors.YELLOW}Step 3: Encryption Process{Colors.END}")
    print_status("Applying XOR encryption algorithm...", "INFO")
    loading_animation(1.0)
    ciphertext_bytes = xor_bytes(plaintext, key)
    print_status("XOR encryption completed successfully", "SUCCESS")

    # 4) Encode ciphertext to Base64 for safe text file storage
    print_status("Encoding ciphertext to Base64...", "INFO")
    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")
    print_status("Base64 encoding completed", "SUCCESS")

    # 5) Compute key hash (hex)
    print_status("Computing cryptographic hash...", "INFO")
    key_hash = sha256_hex(key)
    print_status("SHA-256 hash computed", "SUCCESS")

    # 6) Choose common index to keep files paired
    idx = next_index(DIRS["encrypted"], BASE_NAMES["enc"], "txt")

    # 7) Save files with auto-incremented names
    print_status("Securing files to disk...", "INFO")
    enc_path  = build_name(DIRS["encrypted"], BASE_NAMES["enc"], idx, "txt")
    rawk_path = build_name(DIRS["keys"],      BASE_NAMES["key_raw"], idx, "bin")  # raw key bytes
    hash_path = build_name(DIRS["keys"],      BASE_NAMES["key_hash"], idx, "txt") # hex hash

    save_text(enc_path, ciphertext_b64)
    save_bytes(rawk_path, key)
    save_text(hash_path, key_hash)

    # 8) Log everything (and make a simple mapping line)
    log("Encryption",
        f"enc={os.path.basename(enc_path)} | key_raw={os.path.basename(rawk_path)} | key_hash={os.path.basename(hash_path)} | plaintext_bytes={len(plaintext)}")
    log("Key Generated", f"bytes={len(key)} | hash={key_hash}")

    print_section_header("🎯 ENCRYPTION COMPLETE")
    print_status("All operations completed successfully!", "SUCCESS")
    print(f"\n{Colors.GREEN}📁 Encrypted file : {Colors.END}{enc_path}")
    print(f"{Colors.YELLOW}🔑 Key (RAW) file : {Colors.END}{rawk_path}")
    print(f"{Colors.CYAN}🔒 Key (HASH) file: {Colors.END}{hash_path}")
    print(f"\n{Colors.RED}{Colors.BOLD}⚠️  SECURITY NOTICE: {Colors.END}")
    print(f"{Colors.RED}Keep the RAW key file safe. You need it to decrypt. The hash is for verification only.{Colors.END}")

# ====== DECRYPT ======
def find_index_from_enc_filename(enc_path: str) -> int | None:
    bn = os.path.basename(enc_path)
    m = re.match(rf"^{re.escape(BASE_NAMES['enc'])}(\d*)\.txt$", bn)
    if not m:
        return None
    return int(m.group(1)) if m.group(1) else 0

def decrypt_flow():
    print_section_header("🔓 DECRYPTION MODULE")
    print_status("Initializing decryption protocol...", "INFO")
    
    print(f"\n{Colors.CYAN}Decryption mode selection:{Colors.END}")
    print(f"  {Colors.GREEN}A){Colors.END} Auto (recommended): Pick encrypted file, program finds matching RAW key")
    print(f"  {Colors.GREEN}B){Colors.END} Manual: Paste original key and select HASH file to verify")
    print(f"  {Colors.GREEN}C){Colors.END} Show all decrypted files with paths")
    mode = input(f"{Colors.YELLOW}Select (A/B/C): {Colors.END}").strip().upper()

    if mode == "A":
        print(f"\n{Colors.YELLOW}Auto Decryption Mode{Colors.END}")
        enc_path = input(f"{Colors.CYAN}Enter path to encrypted file (Base64): {Colors.END}").strip('"').strip()
        if not os.path.isfile(enc_path):
            print_status("Encrypted file not found. Aborting operation.", "ERROR")
            return
        
        print_status("Analyzing encrypted file...", "INFO")
        idx = find_index_from_enc_filename(enc_path)
        if idx is None:
            print_status("Invalid filename pattern. Must follow 'encrypted_data.txt' or 'encrypted_dataN.txt'", "ERROR")
            return

        rawk_path = build_name(DIRS["keys"], BASE_NAMES["key_raw"], idx, "bin")
        if not os.path.isfile(rawk_path):
            print_status(f"Matching RAW key file not found: {rawk_path}", "ERROR")
            return

        # Optionally verify against saved hash (if present)
        print_status("Loading encryption key...", "INFO")
        hash_path = build_name(DIRS["keys"], BASE_NAMES["key_hash"], idx, "txt")
        stored_hash = None
        if os.path.isfile(hash_path):
            with open(hash_path, "r", encoding="utf-8") as f:
                stored_hash = f.read().strip()

        print_status("Reading encrypted data...", "INFO")
        with open(enc_path, "r", encoding="utf-8") as f:
            ciphertext_b64 = f.read().strip()
        ciphertext_bytes = base64.b64decode(ciphertext_b64)

        with open(rawk_path, "rb") as f:
            key = f.read()

        if stored_hash and sha256_hex(key) != stored_hash:
            print_status("Key hash verification failed. Files may be mismatched.", "ERROR")
            return

        print_status("Applying decryption algorithm...", "INFO")
        loading_animation(1.5)
        plaintext = xor_bytes(ciphertext_bytes, key)

        # Display the decrypted content
        print_section_header("🔓 DECRYPTED CONTENT")
        try:
            # Try to decode as UTF-8 text first
            decrypted_text = plaintext.decode("utf-8")
            print(f"{Colors.GREEN}{decrypted_text}{Colors.END}")
        except UnicodeDecodeError:
            # If it's not valid UTF-8, show as hex
            print(f"{Colors.YELLOW}Binary data detected. Displaying in hexadecimal format:{Colors.END}")
            print(f"{Colors.CYAN}{plaintext.hex()}{Colors.END}")
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")

        print_status("Saving decrypted content...", "INFO")
        idx_out = next_index(DIRS["decrypted"], BASE_NAMES["dec"], "txt")
        dec_path = build_name(DIRS["decrypted"], BASE_NAMES["dec"], idx_out, "txt")
        save_bytes(dec_path, plaintext)
        log("Decryption", f"enc={os.path.basename(enc_path)} | key_raw={os.path.basename(rawk_path)} | out={os.path.basename(dec_path)}")
        
        print_section_header("🎯 DECRYPTION COMPLETE")
        print_status("Decryption operation completed successfully!", "SUCCESS")
        print(f"{Colors.GREEN}📁 Decrypted file: {Colors.END}{dec_path}")

    elif mode == "B":
        # Manual: user pastes original key; we verify against a chosen hash file
        print(f"\n{Colors.YELLOW}Manual Decryption Mode{Colors.END}")
        enc_path = input(f"{Colors.CYAN}Enter path to encrypted file (Base64): {Colors.END}").strip('"').strip()
        if not os.path.isfile(enc_path):
            print_status("Encrypted file not found. Aborting operation.", "ERROR")
            return

        print_status("Reading encrypted data...", "INFO")
        with open(enc_path, "r", encoding="utf-8") as f:
            ciphertext_b64 = f.read().strip()
        ciphertext_bytes = base64.b64decode(ciphertext_b64)

        print_status(f"Ciphertext requires a key of exactly {len(ciphertext_bytes)} bytes", "INFO")
        key_str = input(f"{Colors.CYAN}Paste ORIGINAL key (must match length exactly): {Colors.END}")
        key = key_str.encode("utf-8")
        if len(key) != len(ciphertext_bytes):
            print_status("Key length mismatch detected. Aborting operation.", "ERROR")
            return

        hash_path = input(f"{Colors.CYAN}Enter path to key HASH file (key_hash*.txt): {Colors.END}").strip('"').strip()
        if not os.path.isfile(hash_path):
            print_status("Hash file not found. Aborting operation.", "ERROR")
            return

        print_status("Verifying key against stored hash...", "INFO")
        with open(hash_path, "r", encoding="utf-8") as f:
            stored_hash = f.read().strip()

        if sha256_hex(key) != stored_hash:
            print_status("Key verification failed. Are you sure this is the exact original key?", "ERROR")
            return

        print_status("Key verification successful. Applying decryption...", "INFO")
        loading_animation(1.5)
        plaintext = xor_bytes(ciphertext_bytes, key)
        
        # Display the decrypted content
        print_section_header("🔓 DECRYPTED CONTENT")
        try:
            # Try to decode as UTF-8 text first
            decrypted_text = plaintext.decode("utf-8")
            print(f"{Colors.GREEN}{decrypted_text}{Colors.END}")
        except UnicodeDecodeError:
            # If it's not valid UTF-8, show as hex
            print(f"{Colors.YELLOW}Binary data detected. Displaying in hexadecimal format:{Colors.END}")
            print(f"{Colors.CYAN}{plaintext.hex()}{Colors.END}")
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")

        print_status("Saving decrypted content...", "INFO")
        idx_out = next_index(DIRS["decrypted"], BASE_NAMES["dec"], "txt")
        dec_path = build_name(DIRS["decrypted"], BASE_NAMES["dec"], idx_out, "txt")
        save_bytes(dec_path, plaintext)
        log("Decryption", f"enc={os.path.basename(enc_path)} | manual_key_used | out={os.path.basename(dec_path)}")
        
        print_section_header("🎯 DECRYPTION COMPLETE")
        print_status("Decryption operation completed successfully!", "SUCCESS")
        print(f"{Colors.GREEN}📁 Decrypted file: {Colors.END}{dec_path}")

    elif mode == "C":
        # Show all decrypted files with paths
        print_section_header("📁 FILE MANAGEMENT")
        print_status("Scanning decrypted files directory...", "INFO")
        
        decrypted_files = []
        if os.path.exists(DIRS["decrypted"]):
            for filename in os.listdir(DIRS["decrypted"]):
                if filename.endswith(".txt"):
                    file_path = os.path.join(DIRS["decrypted"], filename)
                    file_size = os.path.getsize(file_path)
                    # Get file modification time
                    mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    decrypted_files.append((filename, file_path, file_size, mod_time))
        
        if decrypted_files:
            # Sort by modification time (newest first)
            decrypted_files.sort(key=lambda x: x[3], reverse=True)
            
            print_status(f"Found {len(decrypted_files)} decrypted file(s)", "SUCCESS")
            print(f"\n{Colors.CYAN}{Colors.BOLD}DECRYPTED FILES INVENTORY:{Colors.END}")
            print(f"{Colors.DARK_GRAY}{'─'*60}{Colors.END}")
            
            for i, (filename, file_path, file_size, mod_time) in enumerate(decrypted_files, 1):
                print(f"{Colors.GREEN}{i:2d}.{Colors.END} {Colors.YELLOW}{filename}{Colors.END}")
                print(f"    {Colors.CYAN}Path:{Colors.END} {file_path}")
                print(f"    {Colors.BLUE}Size:{Colors.END} {file_size} bytes")
                print(f"    {Colors.DARK_GRAY}Modified:{Colors.END} {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
                print()
        else:
            print_status("No decrypted files found in the directory.", "WARNING")
        
        print(f"{Colors.DARK_GRAY}{'─'*60}{Colors.END}")
        
    else:
        print_status("Invalid selection detected. Please choose A, B, or C.", "ERROR")

# ====== MAIN MENU ======
def main():
    while True:
        print_banner()
        
        print(f"{Colors.CYAN}{Colors.BOLD}MAIN MENU:{Colors.END}")
        print(f"{Colors.DARK_GRAY}{'─'*50}{Colors.END}")
        print(f"  {Colors.GREEN}1){Colors.END} 🔐 Encrypt Data")
        print(f"  {Colors.GREEN}2){Colors.END} 🔓 Decrypt Data")
        print(f"  {Colors.GREEN}3){Colors.END} 🚪 Exit")
        print(f"{Colors.DARK_GRAY}{'─'*50}{Colors.END}")
        
        choice = input(f"{Colors.YELLOW}Select an option (1-3): {Colors.END}").strip()
        
        if choice == "1":
            encrypt_flow()
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        elif choice == "2":
            decrypt_flow()
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        elif choice == "3":
            print_status("Shutting down OTP Encryption Suite...", "INFO")
            loading_animation(1.0)
            print_status("Goodbye! Stay secure!", "SUCCESS")
            break
        else:
            print_status("Invalid selection. Please choose 1, 2, or 3.", "ERROR")
            time.sleep(1)

if __name__ == "__main__":
    main()
