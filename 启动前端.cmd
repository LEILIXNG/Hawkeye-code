@echo off
cd /d "%~dp0"

powershell -NoProfile -Command "foreach($p in 8000..8020){try{$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$p);$l.Start();$l.Stop();$p;break}catch{}}" > "%TEMP%\hawkeye_port.txt"
set /p PORT=<"%TEMP%\hawkeye_port.txt"
del "%TEMP%\hawkeye_port.txt"
if not defined PORT set PORT=8000

echo Starting Hawkeye at http://localhost:%PORT%  (close this window to stop)
start "" /min powershell -NoProfile -Command "Start-Sleep -Seconds 3; Start-Process 'http://localhost:%PORT%'"
python -m uvicorn apps.api.main:app --port %PORT%
echo.
echo Server stopped.
pause
