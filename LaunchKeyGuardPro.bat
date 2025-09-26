@echo off
title KeyGuard Pro - Advanced Keylogger Detection System
color 0C
echo.
echo  ================================================================
echo                    KeyGuard Pro v1.0
echo           Advanced Keylogger Detection System
echo  ================================================================
echo.
echo  This application provides comprehensive protection against
echo  keyloggers and malicious input monitoring software.
echo.
echo  Features:
echo  * Advanced process scanning with AI-powered detection
echo  * Real-time keyboard hook monitoring
echo  * Safe process termination with system protection
echo  * Input monitoring playground for testing
echo  * Dark-themed modern interface
echo.
echo  IMPORTANT: Administrator privileges are required for full
echo  functionality including system-wide process access.
echo.
echo  ================================================================
echo.
pause

echo Starting KeyGuard Pro...
cd /d "%~dp0"

if exist "Release\KeyloggerDetector.exe" (
    echo Running release version...
    powershell -Command "Start-Process '%~dp0Release\KeyloggerDetector.exe' -Verb RunAs"
) else (
    echo Release version not found. Running development version...
    powershell -Command "Start-Process 'dotnet' -ArgumentList 'run KeyloggerDetector.csproj' -Verb RunAs"
)

echo.
echo KeyGuard Pro has been launched with administrator privileges.
echo Check the application window that should have opened.
echo.
pause
