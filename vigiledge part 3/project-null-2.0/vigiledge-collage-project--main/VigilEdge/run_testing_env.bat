@echo off
echo ========================================
echo    VigilEdge WAF Testing Environment
echo ========================================
echo.
echo Starting vulnerable target application...
echo WARNING: This contains intentional vulnerabilities!
echo.

REM Start the vulnerable app in background
start "Vulnerable Target" cmd /c "python vulnerable_app.py"

echo.
echo Vulnerable target started on http://localhost:8080
echo.
echo Starting VigilEdge WAF...
echo.

REM Start the WAF
python main.py

pause
