@echo off
REM run_tests.bat - runs every unit test built by build.bat. Stops at the first failure.
cd /d "%~dp0"
if exist C:\msys64\ucrt64\bin set PATH=C:\msys64\ucrt64\bin;%PATH%
for %%T in (test_deque test_hashtable test_heap test_circular_queue test_linkedlist test_stack test_parser test_detector test_simulator test_evaluation test_api test_server) do (
    echo ===== %%T =====
    %%T.exe
    if errorlevel 1 ( echo [FAIL] %%T & exit /b 1 )
)
echo ALL UNIT TESTS PASSED
