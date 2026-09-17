#Requires -RunAsAdministrator
<#
.SYNOPSIS
    HijackRange lab setup for DLLHijackHunter Arsenal demo.

.DESCRIPTION
    Installs three deliberately vulnerable scenarios:

    Alpha  - Windows service (HijackRangeAlpha) as SYSTEM. Binary dir
             C:\HijackRange\Alpha\ has BUILTIN\Users:MODIFY. Statically
             imports alpha_payload.dll -> SearchOrder hijack.
             Expected: CONFIRMED / 100% / HIGH (SYSTEM + SeDebugPrivilege)

    Beta   - Scheduled task (HijackRangeBeta) as SYSTEM. Same pattern
             with beta_plugin.dll. Demonstrates ScheduledTask trigger.

    Gamma  - Writable directory prepended to system PATH. No binary needed;
             scanner detects global-hijack DLLs (wlbsctrl/IKEEXT etc.).

.NOTES
    Run build-all.bat first to compile the binaries.
    Teardown: .\teardown.ps1
#>

param([switch]$SkipGamma)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root      = "C:\HijackRange"
$AlphaDir  = "$Root\Alpha"
$BetaDir   = "$Root\Beta"
$GammaDir  = "$Root\Gamma"
$ScriptDir = $PSScriptRoot

function Write-Step { param($m) Write-Host "  [*] $m" -ForegroundColor Cyan   }
function Write-OK   { param($m) Write-Host "  [+] $m" -ForegroundColor Green  }
function Write-Warn { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }

function Set-WeakAcl ([string]$Path) {
    $acl  = Get-Acl $Path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Users","Modify",
                "ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $Path $acl
}

# Sanity check
$missing = @()
if (-not (Test-Path "$ScriptDir\Alpha\HijackAlpha.exe"))  { $missing += "Alpha\HijackAlpha.exe"  }
if (-not (Test-Path "$ScriptDir\Alpha\alpha_payload.dll")) { $missing += "Alpha\alpha_payload.dll" }
if (-not (Test-Path "$ScriptDir\Beta\HijackBeta.exe"))    { $missing += "Beta\HijackBeta.exe"    }
if (-not (Test-Path "$ScriptDir\Beta\beta_plugin.dll"))   { $missing += "Beta\beta_plugin.dll"   }
if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "  [!] Missing binaries - run build-all.bat first:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "  HijackRange Lab Setup" -ForegroundColor Magenta
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

# ---- Alpha (service) --------------------------------------------------------
Write-Host "  [Alpha] Service -> SYSTEM" -ForegroundColor White

# Stop and remove stale service BEFORE copying so the binary is not locked
$svc = Get-Service "HijackRangeAlpha" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Warn "Removing stale HijackRangeAlpha (waiting for file lock to clear)"
    try { & sc.exe stop "HijackRangeAlpha" 2>&1 | Out-Null } catch {}
    Start-Sleep 4
    try { & sc.exe delete "HijackRangeAlpha" 2>&1 | Out-Null } catch {}
    Start-Sleep 2
}

Write-Step "Creating $AlphaDir"
New-Item -ItemType Directory -Force -Path $AlphaDir | Out-Null
Write-Step "Copying binaries"
Copy-Item "$ScriptDir\Alpha\HijackAlpha.exe"   $AlphaDir -Force
Copy-Item "$ScriptDir\Alpha\alpha_payload.dll" $AlphaDir -Force
Write-Step "Setting weak ACL"
Set-WeakAcl $AlphaDir

Write-Step "Installing HijackRangeAlpha service"
$binPath = "`"$AlphaDir\HijackAlpha.exe`""
sc.exe create HijackRangeAlpha binPath= $binPath start= auto obj= LocalSystem DisplayName= "HijackRange Alpha" | Out-Null
sc.exe description HijackRangeAlpha "Deliberately vulnerable service for DLLHijackHunter demo" | Out-Null
sc.exe start HijackRangeAlpha | Out-Null
Start-Sleep 2
$svc = Get-Service "HijackRangeAlpha" -ErrorAction SilentlyContinue
if ($svc.Status -eq "Running") { Write-OK "HijackRangeAlpha RUNNING as SYSTEM" }
else { Write-Warn "Status: $($svc.Status)" }

# ---- Beta (scheduled task) --------------------------------------------------
Write-Host ""
Write-Host "  [Beta] Scheduled Task -> SYSTEM" -ForegroundColor White
Write-Step "Creating $BetaDir"
New-Item -ItemType Directory -Force -Path $BetaDir | Out-Null
Write-Step "Copying binaries"
Copy-Item "$ScriptDir\Beta\HijackBeta.exe"  $BetaDir -Force
Copy-Item "$ScriptDir\Beta\beta_plugin.dll" $BetaDir -Force
Write-Step "Setting weak ACL"
Set-WeakAcl $BetaDir

try { & schtasks.exe /delete /tn "HijackRangeBeta" /f 2>&1 | Out-Null } catch {}

$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Deliberately vulnerable task - DLLHijackHunter Arsenal demo</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$BetaDir\HijackBeta.exe</Command>
      <WorkingDirectory>$BetaDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

Write-Step "Registering HijackRangeBeta scheduled task"
$tmp = [IO.Path]::GetTempFileName() + ".xml"
[IO.File]::WriteAllText($tmp, $xml, [Text.Encoding]::Unicode)
schtasks.exe /create /tn "HijackRangeBeta" /xml $tmp /f | Out-Null
Remove-Item $tmp -ErrorAction SilentlyContinue
Write-OK "HijackRangeBeta registered (SYSTEM, runs on boot + on-demand)"

# ---- Gamma (PATH hijack) ----------------------------------------------------
if (-not $SkipGamma) {
    Write-Host ""
    Write-Host "  [Gamma] Writable PATH directory" -ForegroundColor White
    New-Item -ItemType Directory -Force -Path $GammaDir | Out-Null
    Set-WeakAcl $GammaDir
    $curPath = [Environment]::GetEnvironmentVariable("Path","Machine")
    if ($curPath -notlike "*HijackRange\Gamma*") {
        [Environment]::SetEnvironmentVariable("Path","$GammaDir;$curPath","Machine")
        Write-OK "$GammaDir prepended to system PATH"
    } else {
        Write-Warn "$GammaDir already in PATH"
    }
}

Write-Host ""
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Lab installed. Run the scanner:" -ForegroundColor Green
Write-Host ""
Write-Host "    DLLHijackHunter.exe --mode static+etw+canary --profile aggressive" -ForegroundColor White
Write-Host ""
Write-Host "  Expected results:" -ForegroundColor Yellow
Write-Host "    Alpha -> CONFIRMED / 100% / HIGH  (NT AUTHORITY\SYSTEM + SeDebugPrivilege)" -ForegroundColor Yellow
Write-Host "    Beta  -> CONFIRMED / 100% / HIGH  (NT AUTHORITY\SYSTEM + SeDebugPrivilege)" -ForegroundColor Yellow
if (-not $SkipGamma) {
    Write-Host "    Gamma -> MEDIUM / ~79%  (static; stop IKEEXT first to promote to CONFIRMED)" -ForegroundColor Yellow
}
Write-Host ""
