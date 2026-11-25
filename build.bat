@echo off
REM build.bat - compile the project with GCC (MinGW-w64 / MSYS2) on Windows.
REM Run from the project folder in PowerShell:  .\build.bat
setlocal
cd /d "%~dp0"
if exist C:\msys64\ucrt64\bin\gcc.exe set PATH=C:\msys64\ucrt64\bin;%PATH%
where gcc >nul 2>nul
if errorlevel 1 (
    echo [ERROR] gcc was not found on PATH.
    echo 1. Install MSYS2 from https://www.msys2.org
    echo 2. In the "MSYS2 UCRT64" shell run:  pacman -S mingw-w64-ucrt-x86_64-gcc
    echo 3. Add C:\msys64\ucrt64\bin to your PATH, then open a NEW PowerShell window.
    exit /b 1
)
gcc --version | findstr /i "gcc"
set CFLAGS=-std=c11 -Wall -Wextra -pedantic -O2 -g
set LIB=backend\deque.c backend\hashtable.c backend\heap.c backend\circular_queue.c backend\linkedlist.c backend\stack.c backend\parser.c backend\detector.c backend\simulator.c backend\baseline.c backend\evaluation.c backend\platform.c backend\json.c backend\app.c backend\api.c backend\server.c

if exist backend\main.c (
    echo Building detector.exe ...
    gcc %CFLAGS% backend\main.c %LIB% -o detector.exe -lws2_32
    if errorlevel 1 ( echo [ERROR] Compilation of detector.exe failed - see the messages above. & exit /b 1 )
    echo OK: detector.exe built.
) else (
    echo main.c not written yet - building the unit tests only.
)

echo Building unit tests ...
for %%T in (test_deque test_hashtable test_heap test_circular_queue test_linkedlist test_stack test_parser test_detector test_simulator test_evaluation test_api test_server) do (
    gcc %CFLAGS% tests\%%T.c %LIB% -o %%T.exe -lws2_32
    if errorlevel 1 ( echo [ERROR] %%T failed to compile. & exit /b 1 )
)
echo OK: unit tests built. Run them with:  .\run_tests.bat
endlocal
