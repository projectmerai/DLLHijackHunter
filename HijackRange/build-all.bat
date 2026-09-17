@echo off
:: HijackRange — build all scenarios
:: Usage: build-all.bat [msvc|mingw]  (auto-detects if omitted)
setlocal
cd /d "%~dp0"
set TOOL=%1
if "%TOOL%"=="" (where cl.exe >nul 2>&1 && set TOOL=msvc || set TOOL=mingw)
echo.
echo  Building HijackRange with: %TOOL%
echo.
pushd Alpha
call build-%TOOL%.bat || (echo [!] Alpha FAILED & popd & exit /b 1)
popd
echo.
pushd Beta
call build-%TOOL%.bat || (echo [!] Beta FAILED & popd & exit /b 1)
popd
echo.
echo  [+] All scenarios built. Run setup.ps1 as admin to install.
echo.
