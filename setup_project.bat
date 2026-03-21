@echo off
color 0A
echo ===================================================
echo   AI CYBERSHIELD - UPDATE & INSTALL SCRIPT
echo ===================================================

:: 1. Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python is not installed! Please install Python 3.10+ and try again.
    pause
    exit /b
)

:: 2. Remove old virtual environment to prevent conflicts
if exist "venv" (
    echo [INFO] Removing old virtual environment (Clean Install)...
    rmdir /s /q venv
)

:: 3. Create a new virtual environment
echo [INFO] Creating new virtual environment...
python -m venv venv

:: 4. Activate environment and upgrade pip
echo [INFO] Activating venv and upgrading pip...
call venv\Scripts\activate
python -m pip install --upgrade pip

:: 5. Install requirements
if exist "requirements.txt" (
    echo [INFO] Installing dependencies from requirements.txt...
    echo [INFO] This might take a few minutes...
    pip install -r requirements.txt
) else (
    color 0C
    echo [ERROR] requirements.txt not found!
    pause
    exit /b
)

echo.
echo ===================================================
echo   INSTALLATION COMPLETE! 
echo ===================================================
echo.
echo To run your project, type:
echo    venv\Scripts\activate
echo    python app.py
echo.
pause