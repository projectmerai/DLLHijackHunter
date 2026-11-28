## v2.7.0 — Canary Safety, Service-State Restore, Real-Target Verified

Safety and accuracy fixes from benchmarking against the HijackRange lab and a real target. Verified on Windows 11 Enterprise (build 26300) with Microsoft Defender and tamper protection on: a 42-scan HijackRange regression with no outcome regressions, no residue and no Defender detections; Checkmk Windows agent 2.2.0p23 (CVE-2024-28827), where a plain `--profile aggressive` scan now finds the hole in the agent's child process, types it SearchOrder and confirms it as SYSTEM, while the fixed 2.2.0p29 reports nothing; and the Windows SDK IP over USB service (CVE-2025-47962), where `--target` or `--restart-services` confirms the CVE's `CRYPTSP.dll` as SYSTEM and the fixed build reports nothing. New exit code 4 (artifacts or service state could not be restored); new flags and JSON fields are additive.

### Canary safety and ETW attribution

Fixes for the first safety defects found on the HijackRange lab (TIER 0B, 2026-11-21). In one aggressive scan, the canary for an ETW finding attributed to `MsMpEng.exe` ran `sc.exe stop WinDefend`, which Defender flagged as `Trojan:Win32/MpTamperSrvDisableAV.H`. A canary that could not be deleted was left at a Users-writable machine-PATH position, and later runs treated it as the original DLL. The tool's own file activity also became findings.

#### Safety
- **Service guard.** One decision, `ServiceGuard.IsGuarded`, covers `LaunchProtected` services, Microsoft security services, binaries under the Defender folders, and an embedded, source-cited list of third-party EDR/AV services. Every stop goes through `ServiceControl`, which cannot build a stop for a guarded service. A guarded service gets no canary (`NotTested` plus the reason), and the ETW phase never sends it `stop`.
- **Artifact manifest.** `%ProgramData%\DLLHijackHunter\artifacts.json` records each canary, sidecar, backup and confirm file before it is placed. It is written atomically and accepted only if owned by SYSTEM or Administrators. A startup sweep deletes hash-matched leftovers, restores backups, and reports the rest.
- **Previous artifacts.** A previous artifact at a deploy path (manifest hash match, or the canary marker) is never backed up or proxied. Runtime proxies now carry an explicit marker.
- **Cleanup on failure.** On a failed cleanup the tool stops the trigger again, retries with backoff, names the holder via the Restart Manager, and schedules `MOVEFILE_DELAY_UNTIL_REBOOT`.
- **Residue.** Anything left behind goes in the JSON `Residue` array, a red console block, and new **exit code 4**.

#### ETW attribution
- The scanner's own PID and all of its descendants, tracked by parent PID, are excluded.
- File opens by security-product processes are not lookups.
- Tool artifacts never become candidates: `*_hhorig.dll`, `*.hijackhunter.bak`, `*.probebak`, the tool folder, and manifest entries.
- Process paths are resolved from the EXE's own image-load event or its command line before `OpenProcess`, so short-lived processes keep their full path. When no full path is found the finding says `binary path unresolved` and `BinaryPath` is empty; it is never a bare name.

#### Scoring
- `Failed` caused by the harness (could not trigger, back up, or stage the sidecar; target directory missing) no longer costs −20. The cause is recorded in `CanaryFailureCause`. `Timeout` keeps −10.

#### Audit
- Every side effect is logged at Info level, with a UTC time and ID, whether or not `--verbose` is set. Each finding carries the same list as `CanaryActions`.

#### New JSON fields (additive; existing names unchanged)
- **Top level:** `ScanId`, `Residue[]` (`Path`, `Role`, `Sha256`, `Holder`, `DelayedDeleteScheduled`, `CandidateId`, `Reason`) and `ArtifactSweep[]` (`Path`, `Role`, `Outcome`, `ScanId`, `Detail`).
- **Per finding:** `CanaryFailureCause`, `CanaryActions[]` (`Utc`, `Action`, `Target`, `Result`) and `BinaryImageName`.

#### Tests
- New `tests/DLLHijackHunter.Tests` (xUnit, `net8.0-windows`) covers the guard, attribution, artifact, cleanup, audit and scoring decisions with no side effects outside a temp directory.

### Fixes from the Checkmk run (CVE-2024-28827)

The real-target run on Checkmk agent 2.2.0p23 confirmed the hole as SYSTEM, and exposed four problems.

#### Typing
- **One typing decision**, `HijackTypeResolver.Classify`, for the ETW FileIOCreate path and the static engine. A real copy later in the process's own search order (System32 for 64-bit, SysWOW64 for 32-bit, then System and Windows; PATH only where the static engine already models it) makes the finding **SearchOrder** with `DllLegitPath` set; **Phantom** only when no copy exists. ETW findings were always Phantom before. The note now states the evidence: "Writable position probed before C:\Windows\SysWOW64\secur32.dll (SearchOrder)".

#### Canary
- **Service children.** For Service triggers the canary waits until the service is stably RUNNING, then up to `--canary-service-wait` seconds (default 90) for the confirm file. Checkmk launches the vulnerable `cmk-agent-ctl.exe` ~31 s after every start; the old ~23 s wait gave up first (two Timeouts) and two other holes fired only from the previous candidate's start. The export-forwarding proxy builder is unchanged: it was not the cause.
- Each fire is timed (`canary-fired` in `CanaryActions`).
- **`host-failed-after-plant`.** A canary that does not fire, where an Application Error 1000, WER 1001 or Application Popup 26 event since the plant names the planted module, is `Failed` with that `CanaryFailureCause`: no penalty, not Confirmed. Otherwise Timeout keeps −10.

#### Service safety
- **Guarded services are never started either.** The ETW phase used to start a stopped guarded service; the tool cannot stop it again, so it was left differing from its snapshot (DoSvc, LaunchProtected=2, on p23).
- **Snapshot once, restore always.** One snapshot (state, start type, PID) per service before the ETW and canary phases; every decision reads it. Every stop and start waits for a stable SCM state (`QueryServiceStatusEx`). After each candidate and at the end of each phase every touched service is restored to its snapshot and verified (3 attempts with backoff). On p23 the targeted run had left `CheckmkService` stopped.
- A service that cannot be restored is residue (`Kind = "service-state"`, `Service`, `ExpectedState`, `ActualState`, `LastError`), a red console block, and **exit code 4** ("artifacts or service state could not be restored").

#### Coverage
- **Service companion executables** (always on, read-only): EXEs in a service's related directories (binary directory, install root, `%ProgramData%\<vendor>`, directories in `ImagePath` arguments and `Parameters`) that a standard user can write to are analysed with the parent's trigger and identity. `DiscoverySource = "companion"`, capped at Medium unless a canary fires or ETW sees the EXE run under that service.
- **`--restart-services`** (opt-in, disruptive): without `--target`, the ETW phase restarts running, non-guarded services with evidence, up to `--restart-cap` (default 20), and logs the plan first.

#### New flags and JSON fields (additive)
- Flags: `--restart-services`, `--restart-cap <n>`, `--canary-service-wait <sec>`.
- `Residue[]`: `Kind`, `Service`, `ExpectedState`, `ActualState`, `LastError`.
- Per finding: `CompanionOf`, `CompanionObserved`; `DiscoverySource` can be `companion`; new `CanaryActions` actions `canary-wait`, `canary-fired`, `service-restore`, `host-failed-after-plant`.

### Cleanup after the Checkmk fixes

- **Scheduled-task leftovers.** A task trigger records the processes its run creates (Task Scheduler parent chain, started after `/run`). When a canary cannot be removed, `/end` is followed by a wait of up to 10 s for those processes; one still holding the canary is terminated, never a process the trigger did not start and never a guarded or security-product image. `task-process-recorded` / `task-process-wait` / `task-process-terminated` in `CanaryActions`.
- **Companion report.** Every executable companion discovery examines is logged (verbose) as kept or rejected with the reason; the end-of-scan summary gives examined / kept / rejected.
- **ETW duplicates.** An ETW finding with an unresolved binary path is merged into a resolved finding with the same DLL and hole directory when the PID or image name matches. File opens attributed to the System process (PID 4) are no longer treated as loader lookups. New field `ObservedPid`.
- **Guard skips visible.** "not starting stopped guarded service" is logged at Info with the guard reason and counted in the summary.
- **Runtime-added directories.** A static Phantom whose binary ETW saw load the same DLL from a directory outside its standard search order becomes SearchOrder (note "Real copy observed loading from <dir> (runtime-added directory)"); otherwise binaries importing SetDllDirectory/AddDllDirectory get a note.
- **DotLocal on 32-bit binaries.** On Windows 11 the loader ignored `<exe>.local` for a 32-bit, unmanifested EXE (Checkmk `cmk-agent-ctl.exe`): an unmodified real `secur32.dll` placed there was never loaded. A 32-bit EXE on 64-bit Windows now gets a DotLocal finding only when `DevOverrideEnable=1`.

### Fixes from the Windows SDK run (CVE-2025-47962)

A real-target run on the Windows SDK "IP over USB" service (`IpOverUsbSvc`, 10.1.26100.3323) confirmed the CVE's `CRYPTSP.dll` hole as SYSTEM, typed SearchOrder; the fixed 10.1.26100.4188 reports nothing. It also found five problems.

- **no false load-probe wins for a .NET image's `mscoree.dll`.** An image with a CLR header gets `mscoree.dll` from the OS loader, which loads it from the system directory without searching the application directory (start trace: no app-directory probe). The static engine no longer emits a SearchOrder/Phantom/EnvPath finding for that import and logs the skip at verbose level. The `--verify-load` probe had reported **Wins** because it resolves the name in the scanner's own child process. General rule: when the probe says Wins but the canary in the target timed out, the finding gets *"Load probe and canary disagree: probe Wins, canary Timeout"* and the probe does not raise its tier; scoring is otherwise unchanged. The `mscoree` rule is based on Windows 11 build 26300.
- **existing files are restored under their exact name.** When a canary or probe position already held a file (the Microsoft `IpOverUsbDiscovery.dll`), the restore used the candidate's lower-case `DllName`, so the file came back as `ipoverusbdiscovery.dll` (content, size and mtime were preserved). The backup now records the on-disk name, SHA-256, size and mtime, restores to that exact path and verifies all four (`file-restore-verified`); a mismatch is residue and exit code 4. The finding gets *"Canary replaced an existing file (writable existing DLL); original restored"*.
- **the first cleanup delete of a loaded canary no longer falls through to a second stop.** Every service canary's first delete failed ("Access denied") and only the retry, after a second stop, succeeded. Measured on the VM: the service's process had already exited, there was no Restart Manager holder (not Defender, not a child process), the error was access denied (never a sharing violation), and the delete succeeded 49–65 ms later: the image was still mapped for a moment after the process exited. After the first failure the cleanup now retries every 50 ms for up to 2 s (`file-deleted ok (bounded retry: …)`), and the failure's audit line records the error type and the holders at that moment. The canary's stops also capture the service's PID and wait up to 10 s for it to exit (`process-exit-wait`, with the PID and the wait time). The stop-again, retry and residue path stays as the fallback. A stop is no longer sent to a service that is already Stopped.
- **stage-ready console output.** One `CONFIRMED  <DLL>  <hole>  <type>  as <identity>  (<trigger>)` line per Confirmed finding, whatever `--format` is; per-event "ETW: ignored open … by the System process (PID 4)" lines go to the log file only (one count line at verbose level); each phase header and summary is printed once; ASCII symbols (`->` for `→`) when the output is redirected or the console is not UTF-8; the fire time is given relative to the plant and the start request ("2.2 s after plant, 0.2 s after start request (before RUNNING)") instead of a negative "after RUNNING"; soft gates are worded as score adjustments; the AutoElevate hunt is skipped (and says so) when `--target` is outside the Windows directory.
- **release build documented.** The release asset `DLLHijackHunter-v2.7.0-win-x64.exe` is `.\build.ps1 -Release -SingleFile` (Release, net8.0-windows, win-x64, self-contained single file). The README's raw `dotnet publish` command now includes `-p:TargetFrameworks=net8.0-windows`, without which it fails on a machine with only the .NET 8 SDK (NETSDK1045). `.\build.ps1` with no switches stays a Debug build.

- **never start a service the tool cannot stop again.** On the VM, `gpsvc` (Group Policy Client) had stopped on its own just before the ETW snapshot; the ETW phase started it, and every `sc stop gpsvc` then failed with OpenService error 5, so the scan ended with service-state residue and exit code 4. Before any phase starts a service the snapshot recorded as Stopped, the tool now opens the SCM and the service with `SERVICE_START | SERVICE_STOP`; if that fails, the service is not started (`not starting stopped service <name>: tool cannot stop it again (<error>)` at Info, counted in the end-of-scan summary next to the guard-skip count). As a fallback, a service the tool started that does not accept a stop (`dwControlsAccepted` without `SERVICE_ACCEPT_STOP`) is not restored but reported as residue of the new kind `service-not-restorable` (exit code 4). The guard, the snapshot and every other residue / exit-4 case are unchanged.
  - **only stable states are judged, and the end of the scan decides.** On the HijackRange VM, `edgeupdate` was started by the ETW phase, was RUNNING with `dwControlsAccepted=0x0` 83 ms later, and was reported as `service-not-restorable` (exit 4), although it stopped on its own (network off) before the scan ended. `dwControlsAccepted` is now read only once the service has reached a stable state. A service that stops on its own right after its start is audited `service <name> stopped on its own after N s`. A RUNNING service without `SERVICE_ACCEPT_STOP` is only provisionally not restorable (audit line, no error). When the residue list is built at the end of the scan, each such service gets a bounded wait (up to 120 s): back in its snapshot state = no residue (`service-not-restorable <name> returned to <state> on its own after N s`), still off it = `service-not-restorable` residue and exit 4, as before. The end-of-scan summary counts the services that returned to their snapshot state on their own.

New `CanaryActions` actions: `process-exit-wait`, `file-restore-verified`, `service-not-restorable`, `service-provisionally-not-restorable`, `service-self-stopped`, `service-self-recovered`; new residue kind `service-not-restorable`. New log level `TRACE` (log file only).

### Known issues

- **Untargeted scans and already-running services.** An auto-start service that is running when the scan starts loaded its start-up DLLs before the ETW trace existed. Without `--target` or `--restart-services` it is not restarted under the trace, so DLLs it loads only at run time are not seen: a plain `--profile aggressive` scan of the SDK's IP over USB service misses the CVE's `CRYPTSP.dll` (it reports the companion finding only). `--target <install dir>` and the disruptive, opt-in `--restart-services` both find and confirm it as SYSTEM.
- **The `mscoree.dll` rule** was verified on Windows 11 build 26300 only; Windows 10 is not yet verified.
- **Overwriting an existing DLL** is reported with its usual type (e.g. SearchOrder) plus a note that the original was restored; a separate "writable existing DLL" type is not part of this release.

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
