# 🔐 OTP Encryption Suite

A secure, hacker-styled One-Time Pad (OTP) encryption tool with a beautiful terminal interface. This tool provides military-grade encryption using XOR operations with cryptographically secure random keys.

## ✨ Features

- **🔐 True OTP Encryption**: One-time pad implementation using cryptographically secure random keys
- **🎨 Hacker Aesthetic**: Beautiful terminal interface with ANSI colors and ASCII art also GUI is there.
- **📁 File Management**: Automatic file naming with incremental suffixes
- **🔑 Key Management**: Secure key generation, storage, and verification
- **📊 Progress Tracking**: Visual progress bars and loading animations
- **📝 Activity Logging**: Comprehensive logging of all operations
- **🔄 Auto-Decryption**: Smart file pairing for seamless decryption
- **🛡️ Hash Verification**: SHA-256 key verification for integrity

## 🚀 Quick Start

### Installation

#### Option 1: Install from PyPI (Recommended)
```bash
pip install otp-encryption-suite
```

#### Option 2: Install from Source
```bash
git clone https://github.com/Ghost-101-ui/otp-encryption-suite.git
cd otp-encryption-suite
pip install -e
python otp.py
#for GUI based
python otp_gui.py

```

#### Option 3: Direct Download
```bash
# Download the standalone script
curl -O https://raw.githubusercontent.com/Ghost-101-ui/otp-encryption-suite/main/otp.py
python otp.py
```

### Usage

After installation, you can run the tool using:

```bash
# Using the installed command
otp-encrypt

# Or the shorter alias
otp

# Or run the Python file directly
python otp.py
```

## 🎯 How It Works

### Encryption Process
1. **Input**: Enter text directly or provide a file path
2. **Key Generation**: Choose between auto-generated secure keys or manual input
3. **Encryption**: XOR encryption with the generated key
4. **Storage**: Save encrypted data, raw key, and key hash with auto-incremented names
5. **Logging**: Record all operations for audit purposes

### Decryption Process
1. **File Selection**: Choose encrypted file or use auto-detection
2. **Key Loading**: Automatically load matching key or verify manual input
3. **Verification**: Hash verification ensures key integrity
4. **Decryption**: XOR decryption with the original key
5. **Output**: Display and save decrypted content

## 📁 File Structure

```
OTP_Encryption_Project/
├── encrypted/          # Encrypted data files (Base64 encoded)
├── decrypted/          # Decrypted output files
├── keys/              # Key files (raw binary + hash)
├── log/               # Activity logs
├── test_files/        # Test data directory
└── otp.py            # Main application
```

## 🔧 Configuration

The tool automatically creates necessary directories and uses relative paths. You can modify the `BASE_DIR` variable in `otp.py` to change the working directory.

## 🛡️ Security Features

- **Cryptographically Secure**: Uses `secrets.token_bytes()` for key generation
- **One-Time Use**: Each key is unique and should never be reused
- **Hash Verification**: SHA-256 verification prevents key tampering
- **Secure Storage**: Keys stored as raw binary files
- **Activity Logging**: Complete audit trail of all operations

## ⚠️ Security Warnings

- **Never reuse keys** - This breaks OTP security
- **Keep raw key files secure** - Anyone with the key can decrypt your data
- **Hash files are for verification only** - They cannot be used to recover keys
- **This is a tool for learning and personal use** - Not intended for production systems

## 🧪 Testing

The tool includes a test files directory where you can experiment safely:

```bash
# Create a test file
echo "Hello, World!" > test_files/test.txt

# Run encryption
python otp.py
# Choose option 1 (Encrypt)
# Select your test file
```

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (uses only standard library)
- Cross-platform support (Windows, macOS, Linux)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Python standard library modules
- Inspired by classic cryptography tools
- Designed for educational and personal security use

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/Ghost-101-ui/otp-encryption-suite/issues) page
2. Create a new issue with detailed information
3. Include your operating system and Python version

---

**Remember**: This tool is for educational purposes and personal use. Always follow security best practices and never reuse encryption keys!



