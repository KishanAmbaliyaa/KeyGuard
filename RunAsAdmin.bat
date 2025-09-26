@echo off
echo Starting KeyGuard Pro with Administrator Privileges...
echo.
echo This application requires administrator access to:
echo - Monitor system processes
echo - Detect keyboard hooks
echo - Terminate suspicious processes
echo.
pause
cd /d "%~dp0"
powershell -Command "Start-Process 'dotnet' -ArgumentList 'run KeyloggerDetector.csproj' -Verb RunAs"
