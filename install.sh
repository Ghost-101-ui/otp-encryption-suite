#!/bin/bash

# OTP Encryption Suite Installation Script
# This script installs the OTP Encryption Suite on Unix-like systems

set -e

echo "🔐 OTP Encryption Suite - Installation Script"
echo "=============================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher first."
    echo "   Visit: https://www.python.org/downloads/"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python $PYTHON_VERSION detected. Python $REQUIRED_VERSION or higher is required."
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3 first."
    exit 1
fi

echo "✅ pip3 detected"

# Upgrade pip
echo "📦 Upgrading pip..."
python3 -m pip install --upgrade pip

# Install the package
echo "📥 Installing OTP Encryption Suite..."
pip3 install -e .

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "You can now use the tool with:"
echo "  otp-encrypt    # Full command"
echo "  otp            # Short alias"
echo "  python otp.py  # Direct script execution"
echo ""
echo "For help and documentation, visit:"
echo "https://github.com/yourusername/otp-encryption-suite"
echo ""
echo "Happy encrypting! 🔐"
