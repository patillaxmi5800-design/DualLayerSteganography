@echo off
REM Run StegoSecure using the project virtual environment.
cd /d "%~dp0"
".venv\Scripts\python.exe" app.py
pause
