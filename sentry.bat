@echo off
:: Sentry Antivirus Launcher
:: Always protects your computer!

title Sentry Antivirus
echo.
echo  =======================================
echo      Sentry Antivirus v1.0.0
echo      Always protects your computer!
echo  =======================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from python.org
    pause
    exit /b 1
)

:: Check if dependencies are installed
python -c "import customtkinter" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

:: Launch Sentry
echo Starting Sentry Antivirus...
python main.py %*

if errorlevel 1 (
    echo.
    echo Sentry encountered an error.
    pause
)
