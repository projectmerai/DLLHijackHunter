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
