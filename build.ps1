# build.ps1 — Build DLLHijackHunter
#
#   .\build.ps1                         Debug build of net8.0-windows into ./build
#   .\build.ps1 -Release -SingleFile    Self-contained single-file exe: ./build/DLLHijackHunter.exe
#   .\build.ps1 -Framework net10.0-windows -Release -SingleFile
#
# The project multi-targets net8.0-windows and net10.0-windows, so every build/publish
# selects one framework explicitly (dotnet publish refuses a multi-targeted project
# without -f, and building net10.0 requires the .NET 10 SDK).
param(
    [switch]$Release,
    [switch]$SingleFile,
    [ValidateSet('net8.0-windows', 'net10.0-windows')]
    [string]$Framework = 'net8.0-windows'
)

$ErrorActionPreference = 'Stop'

$project = Join-Path $PSScriptRoot 'src/DLLHijackHunter/DLLHijackHunter.csproj'
$output  = Join-Path $PSScriptRoot 'build'
$config  = if ($Release) { 'Release' } else { 'Debug' }

# Building on Linux/macOS needs Windows targeting enabled.
$extra = @()
if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    $extra += '-p:EnableWindowsTargeting=true'
}
# Only restore/build the selected framework, so a missing .NET 10 SDK does not fail a net8 build.
$extra += "-p:TargetFrameworks=$Framework"

Write-Host "Building DLLHijackHunter ($config, $Framework)..." -ForegroundColor Cyan

if ($SingleFile) {
    dotnet publish $project `
        -c $config `
        -f $Framework `
        -r win-x64 `
        --self-contained `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -o $output @extra
} else {
    dotnet build $project -c $config -f $Framework -o $output @extra
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed (exit code $LASTEXITCODE)." -ForegroundColor Red
    exit $LASTEXITCODE
}

if ($SingleFile) {
    Write-Host "Single-file binary: $output/DLLHijackHunter.exe" -ForegroundColor Green
} else {
    Write-Host "Build output: $output/" -ForegroundColor Green
}

Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  ./build/DLLHijackHunter.exe --profile safe"
Write-Host "  ./build/DLLHijackHunter.exe --profile aggressive --no-canary --no-etw -o report.html"
Write-Host "  ./build/DLLHijackHunter.exe --profile aggressive --no-canary --no-etw --verify-load -o report.json"
Write-Host "  ./build/DLLHijackHunter.exe --profile redteam -o report.html    # elevated; runs the canary"
