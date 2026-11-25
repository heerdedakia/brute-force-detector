@echo off
REM run.bat - start the detector. Then open the URL it prints (normally http://localhost:8080).
REM Keep this window open while you use the dashboard. Press Ctrl+C here to stop.
cd /d "%~dp0"
if exist C:\msys64\ucrt64\bin set PATH=C:\msys64\ucrt64\bin;%PATH%
if not exist detector.exe (
    echo detector.exe not found. Run .\build.bat first.
    exit /b 1
)
start http://localhost:8080
detector.exe %*
