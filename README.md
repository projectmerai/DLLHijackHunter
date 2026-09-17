<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" />
  <img src="https://img.shields.io/badge/.NET-8.0_%7C_10.0-purple?style=for-the-badge&logo=dotnet" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-2.5.0-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Black%20Hat%20Arsenal-Sector%202026-CC0000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Black%20Hat%20Arsenal-Sector%202026-CC0000?style=for-the-badge&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsOCA0IDgtNE0yIDEybDggNCA4LTQiLz48L3N2Zz4=" />
</p>

<h1 align="center">DLLHijackHunter</h1>
<h4 align="center">By <a href="https://projectmerai.com">ProjectMerai</a></h4>

<p align="center">
  <strong>Automated DLL Hijacking Discovery, Validation, and Confirmation</strong><br/>
  <em>Turning local misconfigurations into weaponized, confirmed attack paths.</em>
</p>

---

## Overview

**DLLHijackHunter** is an automated Windows DLL hijacking detection tool that goes beyond static analysis. It discovers, validates, and confirms DLL hijacking opportunities using a multi-phase pipeline:

1. **Discovery** — Enumerates binaries across services, scheduled tasks, startup items, COM objects, and AutoElevate UAC bypass vectors
2. **Filtration** — Eliminates false positives through intelligent hard and soft gates
3. **Canary Confirmation** — Deploys a harmless canary DLL and triggers the binary to prove the hijack works
4. **Scoring & Reporting** — Ranks findings by exploitability with a tiered confidence system

> Most DLL hijacking tools stop at “this DLL might be hijackable.” DLLHijackHunter attempts to validate it, cross-reference it against known exploit intelligence, and confirm real execution paths where possible.

---

## Architecture

```mermaid
flowchart TB
    subgraph Phase1["Phase 1: Discovery"]
        SE["Static Engine<br/>Services, Tasks, Startup,<br/>COM, Run Keys"]
        AE["AutoElevate Engine<br/>Manifest + COM UAC Bypass"]
        PE["PE Analyzer<br/>Import Tables, Delay Loads,<br/>Manifests, Exports"]
        ETW["ETW Engine<br/>Real-time DLL Load<br/>Monitoring"]
        SO["Search Order<br/>Calculator"]
    end

    subgraph Phase2["Phase 2: Filter Pipeline"]
        direction LR
        HG["Hard Gates<br/>(Binary Kill)"]
        SG["Soft Gates<br/>(Confidence Adj.)"]
    end

    subgraph Phase3["Phase 3: Load Verification (--verify-load)"]
        LP["LoadProbe<br/>Child-process loader test<br/>Probe DLL placed &amp; removed"]
    end

    subgraph Phase4["Phase 4: Canary"]
        CB["Canary DLL Builder"]
        TE["Trigger Executor"]
        VF["Verification"]
    end

    subgraph Phase5["Phase 5: Output"]
        SC["Tiered Scorer"]
        RC["Console Report"]
        RJ["JSON Report"]
        RH["HTML Report"]
    end

    SE --> PE --> SO
    AE --> PE
    ETW --> SO
    SO --> Phase2
    HG --> SG
    Phase2 --> Phase3
    Phase3 --> Phase4
    CB --> TE --> VF
    Phase4 --> Phase5
```

---

## Key Features

### Hijack Type Coverage

| Type | Description | Stealth | Status |
|---|---|---|---|
| **Phantom** | DLL doesn't exist anywhere on disk | High | Implemented |
| **Search Order** | Place DLL earlier in the Windows search order | High | Implemented |
| **Side-Loading** | Abuse legitimate app loading DLLs from its directory | High | Implemented (AutoElevate copy-to-temp path) |
| **.local Redirect** | Hijack via `.local` directory redirection | High | Implemented |
| **ENV PATH** | Weaponization of writable directories in system `PATH` | High | Implemented (curated service/DLL map) |
| **AppInit DLLs** | `AppInit_DLLs` registry abuse | Low | Implemented |
| **AppCert DLLs** | `AppCertDLLs` registry abuse (loads into every `CreateProcess`/`WinExec` caller) | Low | Implemented |
| **CWD** | Current Working Directory hijack | Low | Planned — not currently produced by any discovery path |

> IFEO Debugger entries are enumerated and the referenced binary is analyzed for DLL imports, but there is no dedicated IFEO/KnownDLL-bypass hijack type — those are not advertised as standalone detections.

### UAC Bypass Discovery

DLLHijackHunter includes dedicated UAC bypass discovery:

- **Manifest AutoElevate** — Scans `System32` and `SysWOW64` for EXEs with `<autoElevate>true</autoElevate>` in embedded manifests
- **COM AutoElevation** — Scans `HKLM\SOFTWARE\Classes\CLSID` for COM objects with `Elevation\Enabled=1`
- **Side-Load Simulation** — For AutoElevate binaries that do not call `SetDllDirectory` or `SetDefaultDllDirectories`, simulates the “copy EXE to writable folder + drop DLL” attack path

### Targeted Vulnerability Knowledge Base

- **Targeted vulnerability mapping** — Cross-references discovered imports against a **bundled snapshot of the [HijackLibs](https://hijacklibs.net/) dataset** (≈590 documented DLL entries spanning ≈700 vulnerable executables), embedded as `Resources/hijacklibs.json`. A match boosts confidence and links the finding to its HijackLibs reference page; the absence of a match means nothing. The dataset is data-driven — refresh it by re-downloading `https://hijacklibs.net/api/hijacklibs.json` over that resource (no code changes required). Dataset © the HijackLibs project and contributors.
- **Automated PATH exploitation** — Evaluates writable `PATH` folders and generates hijack candidates for a curated map of native Windows services known to search `PATH` for missing DLLs
- **Expanded phantom DLL hunting** — Searches for a library of high-value phantom DLL opportunities across multiple categories

### Filter Pipeline

The pipeline reduces false positives through two stages:

**Hard Gates**
- API set schema filtering (`api-ms-*`, `ext-ms-*`)
- KnownDLL filtering
- **Attacker-relative** ACL writability validation — a path counts as writable only if an *unprivileged* principal (`Users` / `Authenticated Users` / `Everyone`, plus leak-proof sub-admin service accounts like `LOCAL SERVICE`/`NETWORK SERVICE`) has effective write rights. Crucially, this is computed independently of the token the tool runs under, so running elevated does **not** make `System32`/`Program Files` look writable. This is what makes elevated runs meaningful for LPE triage.

**Soft Gates**
- WinSxS manifest penalty
- Privilege delta analysis
- `LoadLibraryEx` mitigation checks
- Signature validation checks
- Graceful error-handling penalties

---

## Canary Confirmation

Instead of guessing, DLLHijackHunter attempts to prove hijacks work:

```mermaid
sequenceDiagram
    participant H as DLLHijackHunter
    participant B as Canary DLL Builder
    participant T as Trigger Executor
    participant V as Victim Binary

    H->>B: Build canary DLL
    B->>B: Extract precompiled canary<br/>(synthesise proxy via runtime PE surgery)
    B-->>H: canary.dll + confirmation file path
    H->>H: Place DLL at hijack path
    H->>T: Trigger binary execution
    T->>V: Start service / run task / COM activate
    V->>V: Loads canary DLL
    V-->>H: Writes confirmation file<br/>PID, privilege, integrity level
    H->>H: Record: CONFIRMED
    H->>H: Cleanup canary DLL
```

The canary DLL:
- Ships **precompiled for both x64 and x86**, embedded in the scanner, so **no compiler is required at scan time**. The correct architecture is selected to match the victim's bitness and extracted on demand.
- Is **self-locating**: it derives its confirmation-file path at runtime from its own loaded module path (`%ProgramData%\DLLHijackHunter\canary_<hash>.confirm`), so one binary serves every candidate. The scanner computes the same hash from the deploy path and polls for that file.
- Uses a **file-based confirmation mechanism**
- Captures execution metadata such as user, integrity level, and privilege indicators
- Contains no malicious payload; it is strictly a detection and validation mechanism
- Statically links the CRT, so it has **no runtime dependency** (ucrtbase/vcruntime) on the victim host.

The bundled binaries are built from the auditable source at `src/DLLHijackHunter/Resources/canary_src.c` and can be regenerated with `Resources/build_canary.bat` (requires the MSVC C++ toolchain; the scanner does **not**).

> **Functional-proxy exception:** When a search-order hijack targets a DLL that *exists* and exposes exports, keeping the host alive after confirmation requires an export-forwarding **proxy**. DLLHijackHunter generates this proxy at runtime through **PE surgery** — it grafts a synthesised `.edata` section onto the precompiled embedded canary entirely in-process, with no compiler required. The correct forwarder strings are computed from the victim DLL's export table and encoded directly into the binary. Phantom-DLL and other no-export candidates skip this step entirely; no toolchain is ever needed.

> **Signing:** The embedded canaries are unsigned. Code-signing them (so they load under stricter policies and are attributable) requires a signing certificate and is left as a release-time step for the maintainer.

### Export-forwarding proxy canaries

Proxy canaries are generated via **runtime PE synthesis** (no compiler required) and have been validated against real targets including services and scheduled tasks running as `NT AUTHORITY\SYSTEM`. The following edge cases can still cause a proxy canary to report inconclusive even when the underlying hijack is valid:

- ordinal-only exports (name table absent)
- decorated export names (calling-convention mangling mismatches)
- loader/runtime assumptions in the target process that require the *real* DLL to be resident

A failed proxy canary does **not** mean the hijack path is impossible — it means execution confirmation is inconclusive for that specific target.

---

## Load-Order Verification (`--verify-load`)

An **opt-in**, standard-user verification that sits between the filter pipeline and canary phase. For each applicable candidate it briefly writes a benign probe DLL to the writable hijack position, then asks the **real Windows loader** — in a short-lived child process — to resolve the DLL by name. Where the loader resolves determines the verdict:

- **Verified win** — the loader picks the writable position. The search-order claim is *proven* (this corroboration lets the finding reach the High tier; canary execution remains the only path to **Confirmed**).
- **Loses to protected** — the loader picks a KnownDLL, the System32 copy, or a SxS-redirected copy instead. The position is almost certainly **not** hijackable, so the candidate is heavily demoted. This catches the classic false positives a static search-order calculator misses (e.g. a `.local`/search-order "finding" for `ntdll.dll` that KnownDLLs makes unexploitable).

Design and safety notes:

- Runs in a **child process** so a name already loaded into the scanner can't short-circuit the result, and so any load side effect or crash is isolated. No elevation required.
- Each probe is placed, resolved, and then **removed**; any pre-existing file is backed up and restored.
- It models the modern `LOAD_LIBRARY_SEARCH` ordering, so it is only applied to **Phantom / Search-Order / Side-Load** candidates. `.local`, PATH, and AppInit/AppCert candidates use different mechanics and are reported as *Skipped*.
- It writes files transiently to candidate positions (medium-impact); leave it off for fully passive, read-only triage.

```powershell
# Standard-user triage with loader-verified search order (no canary, no ETW)
.\DLLHijackHunter.exe --lpe-only --no-canary --no-etw --verify-load
```

---

## Comparison

| Feature | **DLLHijackHunter** | Robber | DLLSpy | WinPEAS | Procmon |
|---|:---:|:---:|:---:|:---:|:---:|
| Automated discovery | ✅ | ✅ | ✅ | ✅ | ❌ |
| Phantom DLL detection | ✅ | ❌ | ✅ | ❌ | ✅ |
| Search order analysis | ✅ | ❌ | ❌ | ❌ | ❌ |
| ACL-based writability check | ✅ | Partial | ❌ | Basic | ❌ |
| ETW real-time monitoring | ✅ | ❌ | ❌ | ❌ | ✅ |
| Canary confirmation | ✅¹ | ❌ | ❌ | ❌ | ❌ |
| Privilege escalation check | ✅ | ❌ | ❌ | ❌ | ❌ |
| UAC bypass discovery | ✅ | ❌ | ❌ | ❌ | ❌ |
| False positive reduction | ✅² | None | Basic | None | None |
| Reboot persistence check | ✅³ | ❌ | ❌ | ❌ | ❌ |
| Proxy DLL generation | ✅⁴ | ❌ | ❌ | ❌ | ❌ |
| Confidence scoring | ✅ | ❌ | ❌ | ❌ | ❌ |
| Auto trigger (svc/task/COM) | ✅⁵ | ❌ | ❌ | ❌ | ❌ |
| HTML/JSON reporting | ✅ | ❌ | ❌ | TXT | ❌ |
| Threat intel correlation | ✅⁶ | ❌ | ❌ | ❌ | ❌ |
| Automated PATH exploits | ✅ | ❌ | ❌ | ❌ | ❌ |
| Target-specific scanning | ✅ | ❌ | ❌ | ❌ | ✅ |
| Self-contained binary | ✅ | ❌ | ❌ | ✅ | ❌ |

<sub>
¹ Precompiled dual-arch canaries are embedded — **no compiler needed** to confirm a load. Export-forwarding proxies are also generated at runtime via PE surgery — no compiler required; MSVC is a stripped-build fallback only when the embedded precompiled canary binary is absent from the assembly resources.<br/>
² Via attacker-relative ACL writability (see Filter Pipeline). It reduces — it does not eliminate — false positives; soft-gate heuristics (manifest/SxS/LoadLibraryEx) still carry uncertainty. Unverified static findings are now capped below the **High** tier.<br/>
³ Derived from auto-start status, not a verified reboot test.<br/>
⁴ Export-forwarding proxies are generated via runtime PE synthesis (no compiler required); edge cases such as ordinal-only exports or decorated names may limit confirmation on specific targets.<br/>
⁵ Service/Task/COM triggers only; UAC-bypass findings are not canary-triggered.<br/>
⁶ Backed by a bundled snapshot of the HijackLibs dataset (~590 entries); refreshable from hijacklibs.net.
</sub>

---

## Usage

### Prerequisites

- **Windows 10/11** or **Windows Server 2016+**
- **.NET 8.0 or 10.0 Runtime** (or use a self-contained build)
- **Administrator privileges** recommended (required for ETW, canary deployment, and some service triggers)

### Build

```powershell
git clone https://github.com/ghostvectoracademy/DLLHijackHunter.git
cd DLLHijackHunter

# Build (self-contained single file)
dotnet publish src/DLLHijackHunter/DLLHijackHunter.csproj `
    -c Release -r win-x64 --self-contained `
    -p:PublishSingleFile=true -o ./publish

# Or use the build script
.\build.ps1
```

### Quick Start

```powershell
# Full aggressive scan (recommended, requires admin)
.\DLLHijackHunter.exe --profile aggressive

# Safe scan (no file drops, no triggers)
.\DLLHijackHunter.exe --profile safe

# UAC bypass focused scan
.\DLLHijackHunter.exe --profile uac-bypass

# Target a specific binary
.\DLLHijackHunter.exe --target "C:\Program Files\MyApp\app.exe"

# Target by filename (partial match)
.\DLLHijackHunter.exe --target notepad.exe

# Confirmed findings only
.\DLLHijackHunter.exe --profile redteam --format json -o report.json
```

### CLI Options

```text
DLLHijackHunter — Automated DLL Hijacking Detection

Options:
  -p, --profile <profile>        Scan profile [default: aggressive]
                                   aggressive | strict | safe | redteam | uac-bypass
  -o, --output <path>            Output file path (auto-detects format)
  -f, --format <format>          Output format [default: console]
                                   console | json | html
  -t, --target <target>          Target specific binary, directory, or filename.
                                   Also scopes ETW event capture to that process and
                                   suppresses system-wide PATH analysis.
      --min-confidence <value>   Minimum confidence threshold 0-100. When omitted, each
                                   profile's own threshold applies; passing this overrides it.
      --no-canary                Disable canary confirmation
      --no-etw                   Disable ETW runtime discovery
      --verify-load              Verify search order with the real loader (see below).
                                   Standard-user; transiently writes a benign probe.
      --confirmed-only           Only show canary-confirmed findings
      --lpe-only                 Strict LPE hunting: ignore System32/Program Files, show
                                   only standard-user-writable vulnerabilities
      --log-file <path>          Write a diagnostic scan log to file
  -v, --verbose                  Verbose output
```

> Note: `--min-confidence` is only treated as an override when you explicitly pass it. Otherwise the selected profile's threshold is used (e.g. `safe` = 50%, `strict` = 80%).

### Scan Profiles

| Profile | Use Case | Canary | ETW | UAC Bypass | Min Confidence | Triggers |
|---|---|:---:|:---:|:---:|:---:|---|
| **aggressive** | Full audit, lab environments | ✅ | ✅ | ✅ | 15% | Services, Tasks, COM |
| **strict** | High-confidence findings only | ✅ | ✅ | ❌ | 80% | Services, Tasks |
| **safe** | Production systems, read-only | ❌ | ❌ | ❌ | 50% | None |
| **redteam** | Confirmed exploitable only | ✅ | ✅ | ❌ | 50% | Services, Tasks, COM |
| **uac-bypass** | UAC bypass vectors only | ❌ | ❌ | ✅ | 20% | AutoElevate only |

---

## Scoring

Each finding receives confidence and impact signals that are combined into a final prioritization tier.

Typical impact considerations include:
- privilege gained
- trigger reliability
- stealth
- reboot persistence

Confirmed canary execution should be treated as the strongest validation signal.

**Tier gating:** the **High** and **Confirmed** tiers are reserved for findings backed by a proof signal — a fired canary, an ETW runtime load observation, or a documented knowledge-base match. A purely static search-order match, however clean, is capped at the top of the **Medium** tier and annotated as `Static-only` so unverified heuristics never present as high-confidence.

### Recommended triage configuration

Because writability is evaluated **attacker-relative**, both elevated and standard-user runs are meaningful:

- For LPE triage, the most trustworthy configuration is a **standard-user run with `--lpe-only`** — every surviving finding is genuinely writable by an unprivileged principal. Add `--no-canary` only when passive, no-file-drop operation is required; no compiler is needed for canary mode.
- Elevated runs are required for ETW and canary confirmation, and are now safe from the historical "everything in System32 looks writable" inversion.

---

## Safety

DLLHijackHunter is designed for defensive security research, lab validation, auditing, and red-team simulation in authorized environments.

Use it only on systems and networks you own or are explicitly authorized to assess.

### Operational notes

- Canary mode writes test DLLs to candidate locations
- Some triggers may briefly start or stop services/tasks during validation
- Proxy/export-forwarding canaries may destabilize fragile targets
- Safe profile is the preferred mode for production triage when file drops and triggers are not acceptable

---

## Output

DLLHijackHunter supports:
- console reporting
- JSON export
- HTML export

Recommended workflow:
1. run a broad scan
2. review high-confidence findings
3. use canary confirmation selectively on high-value paths
4. preserve JSON/HTML output for reporting and triage

---

## License

MIT

---

## Credits

Built by **[ProjectMerai](https://projectmerai.com)**.
