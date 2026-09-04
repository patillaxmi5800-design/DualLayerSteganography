@echo off
title StegoSecure - Dual Layer Steganography

cd /d "%~dp0"

echo ==========================================
echo        StegoSecure Project
echo ==========================================
echo.
echo Starting Flask server...
echo.

start "StegoSecure Server" cmd /k ".venv\Scripts\python.exe app.py"

timeout /t 3 /nobreak >nul

echo Opening StegoSecure in your browser...
start "" "http://127.0.0.1:5000"

echo.
echo StegoSecure is running.
echo Keep the server window open while using the project.