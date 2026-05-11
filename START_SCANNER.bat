@echo off
echo.
echo  ====================================================
echo    NetScan Pro - Industrial Network Scanner
echo  ====================================================
echo.
echo  Starting backend server on port 8765...
echo  Browser will open automatically.
echo.
echo  Press Ctrl+C to stop the server.
echo  ====================================================
echo.
start "" http://localhost:8765
python network_scanner_server.py
pause
