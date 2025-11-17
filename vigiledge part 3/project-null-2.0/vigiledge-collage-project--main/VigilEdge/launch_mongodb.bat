@echo off
echo =====================================
echo  VulnShop MongoDB Edition Launcher
echo =====================================
echo.

echo [1/3] Checking Python environment...
python --version
if %errorlevel% neq 0 (
    echo ERROR: Python not found!
    pause
    exit /b 1
)

echo.
echo [2/3] Setting up MongoDB database...
python setup_mongodb.py
if %errorlevel% neq 0 (
    echo.
    echo ERROR: MongoDB setup failed!
    echo Make sure MongoDB is running on localhost:27017
    echo.
    echo To start MongoDB:
    echo - Download and install MongoDB Community Server
    echo - Run 'mongod' in a terminal
    echo.
    pause
    exit /b 1
)

echo.
echo [3/3] Starting VulnShop MongoDB Edition...
echo.
echo WARNING: This application contains intentional vulnerabilities!
echo FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
echo.
echo Starting server...
python vulnerable_app_mongodb.py

pause
