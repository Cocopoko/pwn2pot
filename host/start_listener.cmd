@echo off
title pwn2pot listener - close this window to stop it
echo pwn2pot listener is running in THIS window.
echo Close the window (or press Ctrl+C) to stop it.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hashcat_bridge_listener.ps1"
echo.
echo Listener stopped. Press any key to close.
pause >nul
