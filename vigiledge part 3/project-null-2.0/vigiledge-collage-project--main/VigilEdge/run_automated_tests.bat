@echo off
REM Automated WAF Testing with TestSprite Integration

echo.
echo ========================================================
echo     VigilEdge WAF - Automated Testing Suite
echo ========================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

echo [Step 1/4] Installing test dependencies...
echo.
pip install -r tests\automated\requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [Step 2/4] Checking if WAF and vulnerable app are running...
echo.

REM Check if services are running
curl -s http://localhost:5000/health >nul 2>&1
if errorlevel 1 (
    echo [WARNING] WAF is not running on port 5000
    echo Please start the WAF first: python main.py
    echo.
    choice /C YN /M "Start WAF now"
    if errorlevel 2 goto :skip_waf_start
    start "VigilEdge WAF" cmd /c "python main.py"
    timeout /t 5 /nobreak >nul
    :skip_waf_start
)

curl -s http://localhost:8080/health >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Vulnerable app is not running on port 8080
    echo Please start it: python vulnerable_app.py
    echo.
    choice /C YN /M "Start vulnerable app now"
    if errorlevel 2 goto :skip_app_start
    start "Vulnerable App" cmd /c "python vulnerable_app.py"
    timeout /t 3 /nobreak >nul
    :skip_app_start
)

echo.
echo [Step 3/4] Running automated test suite...
echo.
echo Test Categories:
echo   - SQL Injection Protection
echo   - XSS Protection
echo   - Path Traversal Protection
echo   - Rate Limiting
echo   - Header Injection Protection
echo   - Command Injection Protection
echo   - Legitimate Traffic Handling
echo   - Performance Overhead
echo.

REM Run pytest with detailed output
pytest tests\automated\test_waf_protection.py -v --tb=short --html=test_reports\automated_test_report.html --self-contained-html

if errorlevel 1 (
    echo.
    echo ========================================================
    echo [FAILED] Some tests failed!
    echo ========================================================
    echo Check test_reports\automated_test_report.html for details
    echo.
) else (
    echo.
    echo ========================================================
    echo [SUCCESS] All tests passed!
    echo ========================================================
    echo.
)

echo [Step 4/4] Test report generated
echo.
echo Report location: test_reports\automated_test_report.html
echo.

REM Open report in browser
choice /C YN /M "Open test report in browser"
if errorlevel 2 goto :end
start test_reports\automated_test_report.html

:end
echo.
echo ========================================================
echo Testing complete!
echo ========================================================
pause
