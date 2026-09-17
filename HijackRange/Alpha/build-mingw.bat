@echo off
setlocal
cd /d "%~dp0"
where x86_64-w64-mingw32-gcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (echo [!] x86_64-w64-mingw32-gcc not found & exit /b 1)
echo [*] Building alpha_payload.dll ...
x86_64-w64-mingw32-gcc -shared -O2 -o alpha_payload.dll alpha_payload.c -Wl,--out-implib,alpha_payload.lib
echo [*] Building HijackAlpha.exe ...
x86_64-w64-mingw32-gcc -O2 -o HijackAlpha.exe HijackAlpha.c -L. -lalpha_payload
if %ERRORLEVEL% NEQ 0 goto :fail
echo [+] Done: HijackAlpha.exe + alpha_payload.dll
exit /b 0
:fail
echo [!] Build FAILED
exit /b 1
