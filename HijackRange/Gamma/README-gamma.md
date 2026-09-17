# HijackRange — Gamma Scenario (PATH Hijack, No Build Required)

Gamma demonstrates a **writable PATH directory** hijack — no custom binary needed.

## What it creates

`C:\HijackRange\Gamma\` is added to the **system PATH** (HKLM) with `BUILTIN\Users:MODIFY` ACL.

This directory sits before `C:\Windows\System32` in the search order, so any DLL
name searched before System32 can be planted there.

DLLHijackHunter's `CheckWritablePathDirectories` cross-references writable PATH
entries against its built-in list of known global hijacks:

| DLL | Service |
|-----|---------|
| wlbsctrl.dll | IKEEXT |
| tsmsisrv.dll | SessionEnv |
| ualapi.dll | Spooler |
| wlanhlp.dll | WlanSvc |
| WptsExtensions.dll | Schedule |

If any of those services are present, the scanner generates findings with
`HijackType.EnvPath` and `RunsAs = NT AUTHORITY\SYSTEM`.

## Setup (handled by setup.ps1)

```powershell
# Creates the directory
New-Item -ItemType Directory -Force "C:\HijackRange\Gamma"

# Weak ACL
$acl  = Get-Acl "C:\HijackRange\Gamma"
$rule = New-Object Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Users","Modify","ContainerInherit,ObjectInherit","None","Allow")
$acl.AddAccessRule($rule)
Set-Acl "C:\HijackRange\Gamma" $acl

# Insert at front of system PATH
$old = [Environment]::GetEnvironmentVariable("Path","Machine")
[Environment]::SetEnvironmentVariable("Path","C:\HijackRange\Gamma;$old","Machine")
```

## Expected scanner output

```
[HIGH] Score: ~8.x | Confidence: ~79% | Impact: ~9
Binary:  C:\Windows\System32\svchost.exe
DLL:     wlbsctrl.dll (EnvPath)
Path:    C:\HijackRange\Gamma\wlbsctrl.dll
Trigger: Service "IKEEXT"
Runs As: NT AUTHORITY\SYSTEM
```

> Note: Gamma findings stay at 79% (static-only) because the IKEEXT service
> is usually already running and the canary engine only works on SERVICE/TASK
> triggers. To promote to CONFIRMED, stop IKEEXT first so the canary can
> restart it fresh.
