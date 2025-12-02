@echo off
REM VigilEdge WAF - Quick Start Script
echo.
echo ====================================
echo        VigilEdge WAF - Starting
echo ====================================
echo.

REM Check if setup was completed
if not exist "vigiledge.db" (
    echo [WARNING] Setup may not be complete
    echo Run setup.bat first to install dependencies
    echo.
)

echo [INFO] Starting VigilEdge WAF...
echo [INFO] Dashboard will be available at: http://127.0.0.1:5000
echo [INFO] API Documentation at: http://127.0.0.1:5000/docs
echo [INFO] Press Ctrl+C to stop the server
echo.

REM Start the WAF
python main.py

pause
