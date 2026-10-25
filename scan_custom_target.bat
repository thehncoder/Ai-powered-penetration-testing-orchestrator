@echo off
title Scan Target - AI Penetration Testing Orchestrator
color 0B
cd /d "%~dp0"

echo ========================================================================
echo   AI-POWERED PENETRATION TESTING ORCHESTRATOR - TARGET SCAN
echo   Multi-Agent VAPT Autonomous Pipeline - by Harshit Nigam
echo ========================================================================
echo.
set /p TARGET_URL="Enter your target URL (e.g. https://example.com or http://localhost:3000): "

if "%TARGET_URL%"=="" (
    echo [ERROR] No URL entered. Exiting.
    pause
    exit /b
)

echo.
echo Choose Testing Intensity:
echo   [1] Safe Mode (Recommended - Non-destructive, ethical, safe for production)
echo   [2] Deep Mode (Intensive recursive fuzzing for staging / test labs)
set /p MODE_CHOICE="Select mode [1 or 2, default is 1]: "

set MODE_FLAG=--safe-mode
if "%MODE_CHOICE%"=="2" (
    set MODE_FLAG=--unsafe
    echo Selected: Deep / Intensive Mode
) else (
    echo Selected: Safe Mode
)

if exist "reports\.latest_html.txt" del "reports\.latest_html.txt"

echo.
echo ========================================================================
echo   Starting autonomous scan against: %TARGET_URL%
echo ========================================================================
echo.

python cli.py --target %TARGET_URL% %MODE_FLAG%

echo.
echo ========================================================================
echo   Checking generated report...
echo ========================================================================

if exist "reports\.latest_html.txt" (
    set /p REPORT_FILE=<"reports\.latest_html.txt"
    echo Opening report: %REPORT_FILE% in your browser...
    start "" "%REPORT_FILE%"
    del "reports\.latest_html.txt"
) else (
    echo.
    echo [ERROR] Could not complete scan for "%TARGET_URL%".
    echo Please make sure the URL is online and reachable from your computer.
)

echo.
echo Done!
pause
