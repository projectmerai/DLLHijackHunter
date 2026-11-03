## v2.6.0 — Audit Fixes, False-Positive Reduction, Windows-Verified Detection

Fixes from an external code audit (9 claims, independently verified) plus a full independent bug hunt. Verified on Windows 10 Pro 26H2 (build 26300) with an inert lab: a writable SYSTEM service and a LaunchProtected one, a task with a SID principal, a Run key, and writable machine-PATH and user-PATH folders. Not yet exercised on Windows: ETW full-path resolution (no ETW candidates on the test host), COM `RunAs` resolution for a SYSTEM-configured server, and the canary changes (the canary was not run). No breaking CLI changes; one new exit code (3).

### Correctness — privilege and identity

**PrivilegeDeltaFilter — measured against the scanner instead of the attacker**
The baseline was the scanner's own integrity level, so an elevated scan scored LOCAL/NETWORK SERVICE and UAC-bypass targets as "same privilege" (dropped by `strict`/`redteam`/`uac-bypass`) and standard-user targets as "lower privilege". The baseline is now a fixed standard user, consistent with the ACL checks.

**Identity resolution**
- Scheduled tasks: SID principals (`S-1-5-18/19/20`) are mapped for every logon type; group principals run as the logged-on member instead of defaulting to SYSTEM; payloads wrapped in `rundll32` / `cmd /c` / `powershell -File` are analysed.
- Run keys and Startup folders are enumerated for every user profile (`HKEY_USERS`, ProfileList), not just the scanner's own account.
- COM `LocalServer32` servers resolve `AppID` → `RunAs` / `LocalService` instead of a hard-coded `VARIES`.
- COM canary confirmations of in-process objects are recorded as *caller context*, since the activator is the scanner.

### False positives removed

- **Machine PATH for services** — service and SYSTEM-task search order and PATH weaponisation used the scanner's PATH, including the user's own entries, which services never search.
- **Drive-root writability** — "create folders" was counted as "can drop a DLL", so `C:\<name>` positions looked writable. File drops now require create-file rights; `.local` folders use a separate create-folder check.
- **KnownDLLs** — read from the live `\KnownDlls` / `\KnownDlls32` object directories plus `ntdll.dll`, not only the registry seed list.
- **API sets** — all `api-ms-*` / `ext-ms-*` names are filtered (previously only `*-win-*`).
- **`.local`** — reported only for EXEs without a manifest (or with IFEO `DevOverrideEnable=1`), since the loader ignores `.local` otherwise.
- **UAC copy & side-load** — no longer generated for COM-elevation entries (including DLLs such as `urlmon.dll`/`shell32.dll`); limited to manifest-autoElevate EXEs, with the trusted-directory requirement noted.
- **Attack chains** — any standard-user-plantable SYSTEM finding is a *Direct Path*; the *Ladder* chain appears only when no direct path exists.

On the test host these changes took a clean install from 18 reported findings (all false positives) to 0.

### Detection improvements

- **KnownDllsFilter** — `.local` candidates are no longer all discarded (the whole `.local` path was previously dead code); only KnownDLL ones are.
- **SignatureVerificationFilter** — protected services are detected from the SCM `LaunchProtected` value, covering new Windows services and third-party AV/EDR, for all service-triggered candidates.
- **ETW** — full process image paths are resolved (the kernel event carries only the short name), already-running processes are seeded, and `--target` matching is consistent with static discovery.
- **AclChecker** — also evaluates `INTERACTIVE` (S-1-5-4).

### Verification (load probe and canary)

- **App-directory model** — the probe placed app-directory positions after System32, reporting real hijacks as `LosesToProtected` (−40). Verified on Windows: 5 of 5 app-dir positions now `Wins`.
- **Antivirus quarantine** — a probe or canary removed by real-time antivirus is reported as inconclusive (probe `Error`, `CanaryResult.Blocked`) instead of `NotResolved` / `LosesToProtected` / `Timeout`.
- Probe failures now carry the loader's Win32 error or the child's exit code.

### CLI, output and robustness

- **`--confirmed-only` without a runnable canary** (not elevated, `--no-canary`, `safe`/`uac-bypass`, or `redteam` unelevated) now exits with **code 3** instead of reporting a false "Findings: 0".
- Report formatters are isolated; one failing no longer prevents the others or the scan summary.
- Console mode no longer drops `hijackhunter_<timestamp>.json` into the working directory; with `--output` the JSON goes to that path.
- A requested report is written even when nothing is discovered.
- New **Informational** tier, so findings between the profile threshold and 20% are no longer silently dropped.
- `IncludePPL=false` profiles now actually drop protected-process candidates.
- The scan mode reflects what actually ran; Spectre markup and HTML output are escaped; the HTML report gains attack chains, load-probe results, source, and knowledge-base references.
- `CommandLineParser`: returns the `.exe` that matched during progressive resolution; handles unquoted `rundll32` paths containing spaces.
- Unobserved task exceptions, enumeration failures, and soft-gate errors are logged instead of swallowed.
- `QueryFullProcessImageNameW` P/Invoke now uses `CharSet.Unicode`.

### Build and documentation

- `build.ps1` selects a target framework (`-Framework`, default `net8.0-windows`); `dotnet publish` previously failed on the multi-targeted project. It also works from PowerShell 7 on Linux/macOS.
- README reworked to match current behaviour: operational-impact table (ETW starts services and runs tasks), result tables for the load probe and canary, tiers, exit codes, HijackRange lab, known limitations, and Black Hat Arsenal Europe 2026 / SecTor 2026 badges.

---

## v2.5.0 — Canary Reliability Fixes + Runtime Proxy Synthesis

Three canary bugs that caused confirmed hijacks to be missed or mis-reported, plus a new compiler-free proxy generation pipeline. No breaking changes.

### Bug Fixes

**TriggerExecutor — Service canary masked by `sc.exe` exit-code oracle**
When a service loads the canary DLL and then crashes (common for export-consuming services), DllMain fires and writes the confirmation file *before* the process exits. `sc start` returns non-zero on a crash, so the old code set `triggered = false` and reported `CanaryResult.Failed` even though the confirm file had already been written. Fixed: `TriggerService` now returns `true` unconditionally after dispatching `sc start`; the canary file poll is the correct oracle and is now the only arbiter.

**CanaryDllBuilder — Proxy forwarder naming causes import-snap failure before DllMain**
`GetForwardModuleBase` used `.hhorig` (dot separator) to name the sidecar, producing strings like `"foo.hhorig.ExportName"`. The Windows PE loader splits forwarder strings at the *first dot*, so this was parsed as module = `foo` (the canary itself) and export = `hhorig.ExportName` — not found, import snap fails before DllMain runs, confirmation file is never written: `CanaryResult.Timeout`. Fixed: separator changed to underscore → `foo_hhorig`, producing the unambiguous single-dot forwarder `"foo_hhorig.ExportName"` that correctly resolves to the sidecar.

**TriggerExecutor — Scheduled-task canary settlement delay too short**
`schtasks /run` is asynchronous: it queues the task and returns almost immediately. The previous 3 s post-trigger delay was insufficient for the scheduler to launch the process and for DllMain to complete. The polling window was opening before the DLL was loaded, producing `CanaryResult.Timeout`. Fixed: post-trigger delay increased from 3 s to 8 s.

**AutoElevateEnumerator + COMEnumerator — LocalServer32 path corruption**
`LocalServer32` registry values are full command lines (e.g. `"C:\Program Files\Foo\bar.exe" /sta`). The old code applied `Trim('"')` directly, which corrupts a quoted-path-with-arguments string and causes the wrong executable to be analyzed. Both enumerators now route through `CommandLineParser.ExtractExecutablePath`, which correctly extracts the executable from any quoted or unquoted command line.

**KnownDllsFilter — incorrect .local bypass logic**
The filter previously passed `.local`-redirect candidates for KnownDLLs as valid findings, on the assumption that `.local` files can bypass KnownDLLs. This was true on Windows XP/2003 but was removed in Vista. On all modern Windows, KnownDLLs are served from the kernel object store (`\KnownDlls\`) and are immune to `.local` redirection. These candidates are now correctly suppressed as false positives.

**SearchOrderCalculator — overwrite attack detection**
Previously the search-order walk stopped as soon as the legitimate DLL was found, skipping positions where the attacker could *overwrite* the existing file in a writable directory. The calculator now checks whether the directory at the legitimate DLL's position is writable by a standard user. If it is, the position is added as an overwrite-attack hijack candidate before the walk terminates.

**FilterPipeline — EnvPath deduplication**
`EnvPath` (writable `%PATH%` directory) candidates represent a `(DLL, directory)` attack slot, not a specific binary. Grouping by `(binary, DLL, directory)` was producing hundreds of identical findings — one per binary that loads the same DLL from the same PATH directory. Candidates of type `EnvPath` are now grouped by `(DLL, directory)`, collapsing duplicates into a single finding and retaining the highest-priority trigger.

**ETWDiscoveryEngine + StaticDiscoveryEngine — `--target` scoping**
ETW event capture now filters to processes whose binary falls under the `--target` path, eliminating unrelated system noise from a targeted scan. `StaticDiscoveryEngine` suppresses system-wide `PATH` analysis when `--target` is set, since PATH weaponization is independent of any specific target binary.

**Program.cs — `--canary-settle` CLI flag**
New flag to override the canary settle window (seconds to wait for the canary DLL to fire after execution is triggered) directly from the command line, independent of the selected profile. Useful for services that load many DLLs at startup and need more headroom than the profile default.

### New Features

**RuntimeProxyBuilder — Compiler-free export-forwarding proxy generation**
Export-forwarding proxy DLLs are now generated entirely at runtime via PE surgery. A synthesised `.edata` section is grafted onto the embedded precompiled canary binary in-process — no MSVC, no `cl.exe`, no `vswhere`/`vcvarsall` required. The Windows loader resolves the forwarder strings to a sidecar copy of the same canary, DllMain fires in both, and the host process survives the load. MSVC is fully retired as a runtime dependency; the complete canary pipeline now works from a single self-contained binary.

### Documentation

**README — Corrected all compiler/MSVC claims**
Multiple sections incorrectly stated MSVC was required for export-forwarding proxy generation. All affected passages corrected: the functional-proxy blockquote now describes the PE surgery approach; the Mermaid sequence diagram, footnotes ¹ and ⁴, the proxy section heading, and the triage recommendation have all been updated to reflect the no-compiler-required reality. The `--target` CLI description now notes that it also scopes ETW event capture and suppresses system-wide PATH analysis.
