@echo off
setlocal
title Portfolio Tracker
cd /d "%~dp0"

echo Starting server...
start "Portfolio Server" python server.py

timeout /t 2 /nobreak >nul

echo Starting Cloudflare Tunnel...
start "Cloudflare Tunnel" cloudflared.exe tunnel run portfolio

echo.
echo Server:  http://localhost:8080
echo Public:  https://invest.brento.store
echo.
echo Both windows must stay open.
pause
