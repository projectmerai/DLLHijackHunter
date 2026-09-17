@echo off
setlocal
cd /d "%~dp0"
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (echo [!] cl.exe not found - run from a Developer Command Prompt & exit /b 1)
echo [*] Building alpha_payload.dll ...
cl.exe /nologo /W3 /O2 /c alpha_payload.c /Foalpha_payload.obj
link.exe /nologo /DLL /OUT:alpha_payload.dll alpha_payload.obj /IMPLIB:alpha_payload.lib
if %ERRORLEVEL% NEQ 0 goto :fail
echo [*] Building HijackAlpha.exe ...
cl.exe /nologo /W3 /O2 /c HijackAlpha.c /FoHijackAlpha.obj
link.exe /nologo /OUT:HijackAlpha.exe HijackAlpha.obj alpha_payload.lib
if %ERRORLEVEL% NEQ 0 goto :fail
del /q *.obj *.lib *.exp 2>nul
echo [+] Done: HijackAlpha.exe + alpha_payload.dll
exit /b 0
:fail
echo [!] Build FAILED
exit /b 1
