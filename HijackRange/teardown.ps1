#Requires -RunAsAdministrator
<#
.SYNOPSIS
    HijackRange teardown - removes all lab artifacts cleanly.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "  HijackRange Teardown" -ForegroundColor Magenta
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray

Write-Host "  [*] Removing HijackRangeAlpha service..." -ForegroundColor Cyan
sc.exe stop   "HijackRangeAlpha" | Out-Null
Start-Sleep 2
sc.exe delete "HijackRangeAlpha" | Out-Null

Write-Host "  [*] Removing HijackRangeBeta scheduled task..." -ForegroundColor Cyan
schtasks.exe /delete /tn "HijackRangeBeta" /f | Out-Null

Write-Host "  [*] Removing C:\HijackRange\Gamma from system PATH..." -ForegroundColor Cyan
$currentPath = [Environment]::GetEnvironmentVariable("Path","Machine")
$newPath = ($currentPath -split ";" | Where-Object { $_ -notlike "*HijackRange\Gamma*" }) -join ";"
[Environment]::SetEnvironmentVariable("Path",$newPath,"Machine")

Write-Host "  [*] Removing C:\HijackRange\ ..." -ForegroundColor Cyan
Start-Sleep 1
Remove-Item "C:\HijackRange" -Recurse -Force -ErrorAction SilentlyContinue

if (Test-Path "C:\HijackRange") {
    Write-Host "  [!] C:\HijackRange still exists - a file may be locked." -ForegroundColor Yellow
    Write-Host "      Reboot and re-run teardown.ps1 if needed." -ForegroundColor Yellow
} else {
    Write-Host "  [+] HijackRange removed cleanly." -ForegroundColor Green
}
Write-Host ""
