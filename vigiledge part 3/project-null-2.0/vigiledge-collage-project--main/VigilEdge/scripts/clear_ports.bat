@echo off
echo Checking for processes using ports 8080-8089...

for /L %%i in (8080,1,8089) do (
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr :%%i') do (
        if not "%%a"=="" (
            echo Found process %%a using port %%i
            echo Killing process %%a...
            taskkill /f /pid %%a >nul 2>&1
        )
    )
)

echo Ports cleared. You can now start the vulnerable app.
pause
