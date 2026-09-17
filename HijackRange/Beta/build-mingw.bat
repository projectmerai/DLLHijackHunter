@echo off
setlocal
cd /d "%~dp0"
where x86_64-w64-mingw32-gcc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (echo [!] x86_64-w64-mingw32-gcc not found & exit /b 1)
x86_64-w64-mingw32-gcc -shared -O2 -o beta_plugin.dll beta_plugin.c -Wl,--out-implib,beta_plugin.lib
x86_64-w64-mingw32-gcc -O2 -o HijackBeta.exe HijackBeta.c -L. -lbeta_plugin
if %ERRORLEVEL% NEQ 0 goto :fail
echo [+] Done: HijackBeta.exe + beta_plugin.dll
exit /b 0
:fail
echo [!] Build FAILED
exit /b 1
