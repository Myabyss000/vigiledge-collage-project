@echo off
REM VigilEdge WAF - Launch Script
REM Uses the correct Python installation path

echo ====================================
echo        VigilEdge WAF - Starting
echo ====================================
echo.
echo [INFO] Starting VigilEdge WAF...
echo [INFO] Dashboard will be available at: http://127.0.0.1:5000
echo [INFO] API Documentation at: http://127.0.0.1:5000/docs
echo [INFO] Press Ctrl+C to stop the server
echo.

"C:\Users\Arghya\AppData\Local\Programs\Python\Python313\python.exe" main.py
