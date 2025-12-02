@echo off
echo ========================================
echo         VigilEdge WAF Demo
echo ========================================
echo.

REM Kill any existing processes on our ports
echo Cleaning up any existing services...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8080') do taskkill /f /pid %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000') do taskkill /f /pid %%a >nul 2>&1

echo Starting Vulnerable Target Application...
start "Vulnerable Target" cmd /c "python vulnerable_app.py"

echo Waiting 3 seconds for vulnerable app to start...
timeout 3 >nul

echo.
echo Testing vulnerable app...
python -c "import requests; print('Vulnerable app status:', requests.get('http://localhost:8080').status_code)"

echo.
echo The setup is ready! Here's what you can do:
echo.
echo 1. DIRECT ATTACK (should work):
echo    http://localhost:8080/products?id=1' OR 1=1--
echo.
echo 2. START WAF: python main.py
echo.  
echo 3. ATTACK THROUGH WAF (should be blocked):
echo    http://localhost:5000/api/v1/test/products?id=1' OR 1=1--
echo.
echo Press any key to exit...
pause >nul
