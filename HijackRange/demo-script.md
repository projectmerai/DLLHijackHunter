# DLLHijackHunter — Black Hat Arsenal Demo Script
## HijackRange Lab · Jogi / ProjectMerai

---

## Before the talk (5 min prep)

```powershell
# In a Developer Command Prompt
cd D:\DLL\DLLHijackHunter\HijackRange
build-all.bat

# Elevated PowerShell
.\setup.ps1

# Confirm lab is clean
sc query HijackRangeAlpha        # should show RUNNING
schtasks /query /tn HijackRangeBeta  # should show Ready
```

Keep two terminals open side by side:
- **Left**: admin PowerShell (for sc query, schtasks)
- **Right**: where you run DLLHijackHunter

---

## Talk flow

### 0 — Set context (2 min)

> "DLL hijacking is one of the oldest, most reliable privesc techniques on Windows.
> The problem isn't knowing it exists — it's finding which specific DLL, on this
> specific machine, actually loads from a path you can write to.
> DLLHijackHunter automates that end-to-end: static analysis, live ETW monitoring,
> and a canary DLL that proves execution before you've touched anything malicious."

---

### 1 — Show what "static only" looks like (2 min)

Run **static mode** first so the audience sees the 79% cap before the reveal:

```
DLLHijackHunter.exe --mode static --profile aggressive
```

Point at any MEDIUM finding. Key phrase to use:

> "79% confidence. The tool found it statically — import table, search order,
> writable path — but won't call it High until it *proves* it.
> That's the 79% cap. A static scanner will call everything High.
> We don't."

---

### 2 — Full mode with canary (main demo, 5 min)

```
DLLHijackHunter.exe --mode static+etw+canary --profile aggressive
```

Watch the progress bar. When canary phase starts, draw attention to it.

**What the audience will see happen:**
1. Static phase — finds Alpha, Beta, and the known Windows DLLs
2. ETW phase — live kernel events, might catch more
3. Canary phase — for Alpha and Beta, watch for:

```
[*] Backing up C:\HijackRange\Alpha\alpha_payload.dll
[*] Deploying canary → C:\HijackRange\Alpha\alpha_payload.dll
[*] Triggering HijackRangeAlpha ... service stopped → started
[*] Polling for confirmation ... 2s ... 4s ...
[✓] CANARY CONFIRMED: Running as NT AUTHORITY\SYSTEM at High integrity with SeDebugPrivilege
```

Then scroll to the top of the findings:

```
┌─#1 [CONFIRMED] Score: 10.0 | Confidence: 100% ──────────────────────
│ Binary:  C:\HijackRange\Alpha\HijackAlpha.exe
│ DLL:     alpha_payload.dll (SearchOrder)
│ Path:    C:\HijackRange\Alpha\alpha_payload.dll
│ Trigger: Service "HijackRangeAlpha"
│ Runs As: NT AUTHORITY\SYSTEM
│ ✓ CANARY CONFIRMED: Running as NT AUTHORITY\SYSTEM at High integrity
│   with SeDebugPrivilege
```

> "Score 10.0. Not an educated guess — proven. The canary DLL ran inside
> the SYSTEM service, wrote a confirmation file, and we read it back.
> alpha_payload.dll is already restored. The service is running again.
> Nothing is broken. This is what proof-of-exploit looks like without
> dropping a payload."

---

### 3 — Attack chain (2 min)

Point at the attack chain section:

> "The tool doesn't just give you individual findings. It correlates them into
> attack paths. Here you see 'The Direct Path' — User to SYSTEM in one hop via
> the Alpha service. If you also had a UAC bypass candidate it would chain that
> into 'The Ladder'. One command gives you the full picture."

---

### 4 — How the canary works (2 min, optional technical deep-dive)

Open `src/DLLHijackHunter/Resources/canary_src.c` on screen (or show the slide):

> "The canary is a minimal C DLL. DllMain opens a confirmation file and writes
> the running user, integrity level, and whether SeDebugPrivilege is present.
> It's compiled fresh per-scan, or falls back to a precompiled embedded binary
> if there's no MSVC toolchain available. The host process gets a proxy DLL
> that forwards the real exports — so the service doesn't crash. After the test
> the original DLL is restored from backup."

---

### 5 — Show ETW live catch (2 min, if time allows)

Reset the lab (keep binaries, just restart service):

```powershell
sc stop HijackRangeAlpha; sc start HijackRangeAlpha
```

Run **ETW-only** mode and trigger the service manually in the other terminal:

```
# Terminal 1 (elevated)
DLLHijackHunter.exe --mode etw --profile aggressive --etw-duration 30

# Terminal 2 (while ETW is running)
sc stop HijackRangeAlpha
sc start HijackRangeAlpha
```

The scanner catches the kernel `ImageLoad` event for `alpha_payload.dll`
loading from a writable path:

> "ETW sees every DLL load at the kernel level. We didn't have to know about
> this service ahead of time — we just watched. That's how you find zero-days
> in software you've never seen before."

---

### 6 — Teardown / closing (1 min)

```powershell
.\teardown.ps1
```

> "The whole lab tears down in 3 seconds — service removed, task removed,
> directory gone, PATH restored. In a real engagement you'd automate cleanup
> the same way."

---

## Audience questions — cheat sheet

| Q | A |
|---|---|
| Why not just check ACLs with icacls? | icacls tells you a path is writable. It doesn't tell you which service loads from there, what privilege it runs at, or whether the DLL search order is actually reached. |
| What about WDAC / AppLocker? | Noted as a future filter. The canary DLL is unsigned — WDAC block would show as a Timeout, not Confirmed. |
| Can it catch in-memory-only DLL loads? | No. It requires a DLL file path on disk. In-memory PE loading (reflective DLL) doesn't go through the Windows DLL search order. |
| What's the false-positive rate? | Static-only: the 79% cap keeps false positives explicitly labelled as unverified. Confirmed findings are by definition true-positives — the DLL loaded and the confirmation file was written. |
| Does it work on Server? | Yes — service and scheduled task triggers work identically. COM trigger has quirks on Server Core (no PowerShell Activator). |
| Where's the source? | github.com/ghostvectoracademy/DLLHijackHunter |

---

## Reset between demos

```powershell
# Stop service so canary can restart it fresh
sc stop HijackRangeAlpha

# Delete any leftover .bak or canary artifacts
Remove-Item C:\HijackRange\Alpha\*.bak   -Force -ErrorAction SilentlyContinue
Remove-Item C:\HijackRange\Alpha\*.json  -Force -ErrorAction SilentlyContinue
Remove-Item C:\HijackRange\Beta\*.bak    -Force -ErrorAction SilentlyContinue

# Restart service
sc start HijackRangeAlpha
```
