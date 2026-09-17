@echo off
setlocal
cd /d "%~dp0"
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (echo [!] cl.exe not found & exit /b 1)
cl.exe /nologo /W3 /O2 /c beta_plugin.c /Fobeta_plugin.obj
link.exe /nologo /DLL /OUT:beta_plugin.dll beta_plugin.obj /IMPLIB:beta_plugin.lib
if %ERRORLEVEL% NEQ 0 goto :fail
cl.exe /nologo /W3 /O2 /c HijackBeta.c /FoHijackBeta.obj
link.exe /nologo /OUT:HijackBeta.exe HijackBeta.obj beta_plugin.lib
if %ERRORLEVEL% NEQ 0 goto :fail
del /q *.obj *.lib *.exp 2>nul
echo [+] Done: HijackBeta.exe + beta_plugin.dll
exit /b 0
:fail
echo [!] Build FAILED
exit /b 1
