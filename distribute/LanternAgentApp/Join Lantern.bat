@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This needs Administrator permission to set up the private network.
    echo A Windows prompt will appear - click Yes.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

if /I "%CD%"=="C:\Lantern" (
    echo.
    echo STOP: this folder IS C:\Lantern, the shared folder.
    echo Move this program to a different folder first - see README.
    echo.
    pause
    exit /b
)

for /f "usebackq tokens=1,2 delims==" %%A in ("config.txt") do (
    if /I "%%A"=="LANTERN_SERVER_URL" set "LANTERN_SERVER_URL=%%B"
    if /I "%%A"=="LANTERN_JOIN_CODE" set "LANTERN_JOIN_CODE=%%B"
)

if "%LANTERN_SERVER_URL%"=="" (
    echo config.txt is missing or LANTERN_SERVER_URL is not set in it. Stopping.
    pause
    exit /b
)

echo.
echo Connecting to %LANTERN_SERVER_URL%
echo Join code: %LANTERN_JOIN_CODE%
echo.

lantern-agent.exe

echo.
echo The agent has stopped. Press any key to close this window.
pause >nul
