@echo off
TITLE SecureNet IDS Launcher
COLOR 0A
CLS

ECHO =================================================
ECHO      SECURENET AI IDS - AUTOMATED LAUNCHER
ECHO =================================================
ECHO.
ECHO [1/3] Starting Backend Server (app.py)...
start "SecureNet Backend" cmd /k "python app.py"
timeout /t 5 >nul

ECHO [2/3] Opening Dashboard...
start http://127.0.0.1:5000

ECHO [3/3] Ready for Simulation!
ECHO.
ECHO To run the Attack Simulation:
ECHO    Run: python attack_simulation.py
ECHO.
ECHO To run Real-Time Sniffer:
ECHO    Run: python sniffer.py --iface "Wi-Fi"
ECHO.
PAUSE
