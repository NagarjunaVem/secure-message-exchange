@echo off
rem Author: Vem Nagarjuna Reddy
rem Roll Number: 20243315
setlocal
cd /d "%~dp0"

where g++ >nul 2>&1
if errorlevel 1 (
    echo Could not find g++.
    echo Add the MSYS2 MinGW-w64 bin folder to PATH and try again.
    pause
    exit /b 1
)

if not exist build mkdir build

echo Building the server...
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src\main_server.cpp src\socket_utils.cpp src\exchange_protocol.cpp src\secure_exchange.cpp src\simplified_idea.cpp src\elgamal.cpp src\whirlpool.cpp -lws2_32 -o build\server.exe
if errorlevel 1 goto build_failed

echo Building the client...
g++ -std=c++17 -Wall -Wextra -Wpedantic -Iinclude src\main_client.cpp src\socket_utils.cpp src\exchange_protocol.cpp src\secure_exchange.cpp src\simplified_idea.cpp src\elgamal.cpp src\whirlpool.cpp -lws2_32 -o build\client.exe
if errorlevel 1 goto build_failed

echo Starting the server window...
start "Secure Message Server" cmd /k ""%CD%\build\server.exe""
timeout /t 2 /nobreak >nul

echo Starting the client window...
start "Secure Message Client" cmd /k ""%CD%\build\client.exe""
echo Enter the server keys in the server window, then enter the message and client keys in the client window.
pause
exit /b 0

:build_failed
echo Build failed. Check the compiler output above.
pause
exit /b 1
