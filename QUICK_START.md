# 🚀 Quick Start Guide

Get up and running with OTP Encryption Suite in minutes!

## ⚡ Installation

### Option 1: From PyPI (Recommended)
```bash
pip install otp-encryption-suite
```

### Option 2: From Source
```bash
git clone https://github.com/yourusername/otp-encryption-suite.git
cd otp-encryption-suite
pip install -e .
```

### Option 3: Direct Download
```bash
# Download the standalone script
curl -O https://raw.githubusercontent.com/yourusername/otp-encryption-suite/main/otp.py
python otp.py
```

## 🎯 Usage

### Run the Tool
```bash
# Using installed command
otp-encrypt

# Or the shorter alias
otp

# Or run directly
python otp.py
```

### Basic Workflow

1. **🔐 Encrypt Data**
   - Choose option 1 from the main menu
   - Enter text or provide a file path
   - Choose key generation method
   - Files are automatically saved with incremental names

2. **🔓 Decrypt Data**
   - Choose option 2 from the main menu
   - Select auto mode (recommended) or manual mode
   - Choose your encrypted file
   - Decrypted content is displayed and saved

## 📁 File Structure

The tool automatically creates these directories:
- `encrypted/` - Your encrypted data files
- `decrypted/` - Decrypted output files
- `keys/` - Encryption keys and hashes
- `log/` - Activity logs
- `test_files/` - Safe testing directory

## 🔑 Security Features

- **True OTP**: Each key is unique and cryptographically secure
- **Hash Verification**: SHA-256 verification prevents tampering
- **Auto-pairing**: Smart file matching for seamless decryption
- **Activity Logging**: Complete audit trail of all operations

## ⚠️ Important Notes

- **Never reuse keys** - This breaks OTP security
- **Keep raw key files secure** - Anyone with the key can decrypt
- **Hash files are for verification only** - They cannot recover keys
- **This is for learning and personal use** - Not for production systems

## 🆘 Need Help?

- **Documentation**: [Full README](README.md)
- **Deployment**: [Deployment Guide](DEPLOYMENT.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/otp-encryption-suite/issues)

## 🧪 Test It Out

```bash
# Create a test file
echo "Hello, World!" > test_files/test.txt

# Run encryption
otp-encrypt
# Choose option 1 (Encrypt)
# Select your test file
# Choose auto key generation
```

---

**Happy Encrypting! 🔐**

Remember: Security is everyone's responsibility. Use this tool wisely and never reuse encryption keys!
