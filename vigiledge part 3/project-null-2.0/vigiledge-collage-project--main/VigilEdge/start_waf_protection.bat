@echo off
REM VigilEdge WAF - Integrated Startup Script
REM This script launches both the WAF and the vulnerable application

echo.
echo ========================================================
echo     VigilEdge WAF - Integrated Protection System
echo ========================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo [Step 1/3] Checking Python environment...
echo.

REM Create logs directory if it doesn't exist
if not exist "logs" mkdir logs

echo [Step 2/3] Starting Vulnerable Test Application...
echo.
echo Starting vulnerable app on http://localhost:8080
echo This application will be PROTECTED by VigilEdge WAF
echo.

REM Start vulnerable app in a new window
start "VulnShop - Protected Application" cmd /c "python vulnerable_app.py"

REM Wait for vulnerable app to start
timeout /t 3 /nobreak >nul

echo [Step 3/3] Starting VigilEdge WAF...
echo.
echo WAF will run on http://localhost:5000
echo Dashboard: http://localhost:5000/admin/dashboard
echo Protected App Access: http://localhost:5000/protected/
echo.
echo ========================================================
echo     IMPORTANT - Access Instructions
echo ========================================================
echo.
echo  DO NOT access vulnerable app directly at :8080
echo  Access it through WAF protection at:
echo.
echo  - WAF Dashboard: http://localhost:5000
echo  - Protected App: http://localhost:5000/protected/
echo.
echo  The WAF will:
echo    - Block SQL Injection attacks
echo    - Block XSS attempts  
echo    - Block suspicious patterns
echo    - Log all security events
echo    - Show real-time alerts
echo.
echo ========================================================
echo.
echo Starting WAF... (Press Ctrl+C to stop both services)
echo.

REM Start WAF in the current window
python main.py

echo.
echo ========================================================
echo Shutting down...
echo.
echo Please close the vulnerable app window manually
echo ========================================================
pause
