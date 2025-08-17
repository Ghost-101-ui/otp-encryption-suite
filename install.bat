@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo 🔐 OTP Encryption Suite - Installation Script
echo ==============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH.
    echo    Please install Python 3.7 or higher first.
    echo    Visit: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check Python version
for /f "tokens=2" %%i in ('python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set PYTHON_VERSION=%%i

if "%PYTHON_VERSION%"=="" (
    echo ❌ Could not determine Python version.
    pause
    exit /b 1
)

echo ✅ Python %PYTHON_VERSION% detected

REM Check if pip is installed
pip --version >nul 2>&1
if errorlevel 1 (
    echo ❌ pip is not installed. Please install pip first.
    pause
    exit /b 1
)

echo ✅ pip detected

REM Upgrade pip
echo 📦 Upgrading pip...
python -m pip install --upgrade pip

REM Install the package
echo 📥 Installing OTP Encryption Suite...
pip install -e .

if errorlevel 1 (
    echo ❌ Installation failed. Please check the error messages above.
    pause
    exit /b 1
)

echo.
echo 🎉 Installation completed successfully!
echo.
echo You can now use the tool with:
echo   otp-encrypt    # Full command
echo   otp            # Short alias
echo   python otp.py  # Direct script execution
echo.
echo For help and documentation, visit:
echo https://github.com/yourusername/otp-encryption-suite
echo.
echo Happy encrypting! 🔐
pause
