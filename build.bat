@echo off
g++ -std=c++11 main.cpp -o labgate.exe -lws2_32
if errorlevel 1 (echo Build failed & pause & exit /b 1)
labgate.exe
pause
