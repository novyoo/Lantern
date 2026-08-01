@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

rem The shared folder is created by the program itself. Running from inside it
rem would mean the program tries to share itself with everyone.
if /I "%CD%"=="C:\Lantern" (
    echo.
    echo STOP: this folder IS C:\Lantern, the shared folder.
    echo Move this program somewhere else first - see the README.
    echo.
    pause
    exit /b
)

if not exist config.txt (
    echo config.txt is missing. It should sit next to this file.
    pause
    exit /b
)

for /f "usebackq tokens=1,* delims==" %%A in ("config.txt") do (
    if /I "%%A"=="LANTERN_SERVER_URL" set "LANTERN_SERVER_URL=%%B"
    if /I "%%A"=="LANTERN_ENROLLMENT_KEY" set "LANTERN_ENROLLMENT_KEY=%%B"
    if /I "%%A"=="LANTERN_JOIN_CODE" set "LANTERN_JOIN_CODE=%%B"
)

if "%LANTERN_SERVER_URL%"=="" (
    echo LANTERN_SERVER_URL is not set in config.txt. Stopping.
    pause
    exit /b
)
if "%LANTERN_ENROLLMENT_KEY%%LANTERN_JOIN_CODE%"=="" (
    echo config.txt has no enrollment key. Ask whoever sent you this folder for one.
    pause
    exit /b
)

where tailscale >nul 2>&1
if errorlevel 1 (
    if not exist "C:\Program Files\Tailscale\tailscale.exe" (
        echo.
        echo Tailscale is not installed yet.
        echo Install it once from https://tailscale.com/download
        echo You do NOT need a Tailscale account - Lantern supplies the key.
        echo.
        echo You can carry on without it: the shared folder and encryption still
        echo work, this laptop just will not be on the private network.
        echo.
        pause
    )
)

echo.
echo Connecting to %LANTERN_SERVER_URL%
echo.

lantern-agent.exe

echo.
echo The agent has stopped. Press any key to close this window.
pause >nul
