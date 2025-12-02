@echo off
echo.
echo ============================================================
echo                VigilEdge WAF - Automatic Setup
echo            Web Application Firewall Installation
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo [INFO] Python found. Checking version...
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.8+ is required
    echo Please upgrade your Python installation
    pause
    exit /b 1
)

echo [SUCCESS] Python version is compatible
echo.

REM Create necessary directories
echo [INFO] Creating project directories...
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "config" mkdir config
if not exist "static" mkdir static
if not exist "templates" mkdir templates
echo [SUCCESS] Directories created
echo.

REM Copy environment file
echo [INFO] Setting up environment configuration...
if not exist ".env" (
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo [SUCCESS] Environment file created from template
    ) else (
        echo [WARNING] No .env.example found, using default .env
    )
) else (
    echo [INFO] Environment file already exists
)
echo.

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Failed to upgrade pip, continuing anyway...
) else (
    echo [SUCCESS] Pip upgraded successfully
)
echo.

REM Install dependencies
echo [INFO] Installing Python dependencies...
echo This may take a few minutes...
python -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    echo Please check your internet connection and try again
    echo You can also try: pip install -r requirements.txt
    pause
    exit /b 1
)
echo [SUCCESS] All dependencies installed successfully
echo.

REM Initialize database (create empty file)
echo [INFO] Initializing database...
if not exist "vigiledge.db" (
    type nul > vigiledge.db
    echo [SUCCESS] Database file created
) else (
    echo [INFO] Database file already exists
)
echo.

REM Test imports
echo [INFO] Testing installation...
python -c "import fastapi, uvicorn, pydantic; print('[SUCCESS] Core dependencies working')" 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] Some dependencies may not be working correctly
    echo Try running the application to see specific errors
) else (
    echo [SUCCESS] Installation test passed
)
echo.

REM Display completion message
echo ============================================================
echo                    Setup Complete!
echo ============================================================
echo.
echo Your VigilEdge WAF is now ready to run!
echo.
echo Next steps:
echo 1. Review and customize .env configuration file
echo 2. Start the WAF: python main.py
echo 3. Open dashboard: http://127.0.0.1:5000
echo 4. View API docs: http://127.0.0.1:5000/docs
echo.
echo Security features enabled:
echo - SQL Injection Protection
echo - XSS Protection
echo - Rate Limiting
echo - IP Blocking
echo - Bot Detection
echo - Real-time Monitoring
echo.
echo For production deployment:
echo - Change SECRET_KEY in .env
echo - Set DEBUG=false
echo - Configure SSL/TLS
echo - Set up proper database
echo.
echo Happy protecting! 🛡️
echo.
pause
