# 🚀 Deployment Guide

This guide will help you deploy your OTP Encryption Suite to GitHub and PyPI.

## 📋 Prerequisites

- Python 3.7 or higher
- Git installed and configured
- GitHub account
- PyPI account (optional, for distribution)

## 🔧 Local Setup

### 1. Initialize Git Repository

```bash
# Initialize git repository
git init

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: OTP Encryption Suite"

# Add remote origin (replace with your GitHub username)
git remote add origin https://github.com/yourusername/otp-encryption-suite.git

# Push to GitHub
git push -u origin main
```

### 2. Test Local Installation

```bash
# Install in development mode
pip install -e .

# Test the package
python test_otp.py

# Test CLI commands
otp-encrypt --help
otp --help
```

## 🌐 GitHub Deployment

### 1. Create GitHub Repository

1. Go to [GitHub](https://github.com) and create a new repository
2. Name it `otp-encryption-suite`
3. Make it public (recommended for open source)
4. Don't initialize with README (we already have one)

### 2. Update Repository URLs

Edit these files to replace `yourusername` with your actual GitHub username:

- `setup.py` - Update the `url` and `project_urls`
- `pyproject.toml` - Update the `project.urls`
- `README.md` - Update all GitHub links
- `install.sh` - Update the documentation URL
- `install.bat` - Update the documentation URL

### 3. Push to GitHub

```bash
# Add all files
git add .

# Commit changes
git commit -m "Update repository URLs and prepare for deployment"

# Push to GitHub
git push origin main
```

### 4. Set Up GitHub Actions (Optional)

The `.github/workflows/python-package.yml` file is already configured for:
- Automated testing on multiple Python versions
- Automated testing on multiple operating systems
- Automated package building
- Automated PyPI deployment on releases

To enable PyPI deployment:
1. Go to your GitHub repository settings
2. Navigate to "Secrets and variables" → "Actions"
3. Add these secrets:
   - `PYPI_USERNAME`: Your PyPI username
   - `PYPI_PASSWORD`: Your PyPI API token

## 📦 PyPI Deployment

### 1. Create PyPI Account

1. Go to [PyPI](https://pypi.org) and create an account
2. Enable two-factor authentication (recommended)
3. Create an API token for automated uploads

### 2. Build and Upload

```bash
# Install build tools
pip install build twine

# Build the package
python -m build

# Upload to PyPI (test first)
twine upload --repository testpypi dist/*

# If test upload works, upload to PyPI
twine upload dist/*
```

### 3. Automated Deployment

With GitHub Actions set up, packages will automatically deploy to PyPI when you:
1. Create a new release on GitHub
2. Tag the release with a version number (e.g., `v1.0.0`)

## 🔄 Updating the Package

### 1. Version Management

Update the version in these files:
- `setup.py` - `version` field
- `pyproject.toml` - `version` field
- `otp_encryption_suite/__init__.py` - `__version__`

### 2. Release Process

```bash
# Update version numbers
# Make changes and commit
git add .
git commit -m "Update to version X.Y.Z"

# Create and push tag
git tag vX.Y.Z
git push origin vX.Y.Z

# Create GitHub release
# GitHub Actions will automatically build and deploy
```

## 📱 Installation Methods

Users can install your package in several ways:

### 1. From PyPI (Recommended)

```bash
pip install otp-encryption-suite
```

### 2. From GitHub

```bash
pip install git+https://github.com/yourusername/otp-encryption-suite.git
```

### 3. From Source

```bash
git clone https://github.com/yourusername/otp-encryption-suite.git
cd otp-encryption-suite
pip install -e .
```

### 4. Using Installation Scripts

```bash
# Unix/Linux/macOS
chmod +x install.sh
./install.sh

# Windows
install.bat
```

## 🧪 Testing

### 1. Local Testing

```bash
# Run the test script
python test_otp.py

# Test the main application
python otp.py

# Test installed commands
otp-encrypt
otp
```

### 2. Package Testing

```bash
# Test package installation
pip install -e .

# Test import
python -c "from otp_encryption_suite import main; print('Import successful')"

# Test uninstall
pip uninstall otp-encryption-suite
```

## 🚨 Troubleshooting

### Common Issues

1. **Import Errors**: Make sure the package is installed with `pip install -e .`
2. **Path Issues**: The tool now uses relative paths instead of hardcoded paths
3. **Permission Issues**: Use `sudo` on Unix systems if needed
4. **Python Version**: Ensure Python 3.7+ is installed

### Getting Help

1. Check the [Issues](https://github.com/yourusername/otp-encryption-suite/issues) page
2. Create a new issue with detailed information
3. Include your operating system and Python version

## 🎯 Next Steps

1. **Documentation**: Add more examples and use cases
2. **Testing**: Add unit tests and integration tests
3. **Features**: Consider adding more encryption algorithms
4. **Security**: Add security audits and vulnerability scanning
5. **Community**: Encourage contributions and feedback

---

**Happy Deploying! 🚀**

Remember to keep your API keys and secrets secure, and never commit them to your repository.
