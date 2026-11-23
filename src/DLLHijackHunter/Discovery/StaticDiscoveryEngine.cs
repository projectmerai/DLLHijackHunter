using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Microsoft.Win32;
using Spectre.Console;
using System.Reflection;
using System.Text.Json;

namespace DLLHijackHunter.Discovery;

public class StaticDiscoveryEngine
{
    private readonly ScanProfile _profile;

    private static readonly Lazy<HashSet<string>> PhantomDllDatabase = new(LoadPhantomDlls);

    // Lazily-built set of all directories listed in %PATH% (case-insensitive on Windows).
    // Used to reclassify hijack candidates whose writable position is in a PATH directory
    // (rather than the binary's own directory) as EnvPath, enabling cross-binary dedup.
    private static readonly Lazy<HashSet<string>> PathDirSet = new(() =>
    {
        var dirs = Environment.GetEnvironmentVariable("PATH")?.Split(';',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            ?? Array.Empty<string>();
        return new HashSet<string>(dirs, StringComparer.OrdinalIgnoreCase);
    });

    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
    //   DevOverrideEnable (DWORD) = 1 → .local redirection honoured even for manifested EXEs.
    private static readonly Lazy<bool> DevOverrideEnabled = new(() =>
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            return key?.GetValue("DevOverrideEnable") is int v && v != 0;
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"Could not read DevOverrideEnable: {ex.Message}");
            return false;
        }
    });

    private static HashSet<string> LoadPhantomDlls()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(
                "DLLHijackHunter.Resources.phantom_dlls.json");
            if (stream == null) return set;

            using var reader = new StreamReader(stream);
            string json = reader.ReadToEnd();

            using var doc = JsonDocument.Parse(json);
            var categories = doc.RootElement.GetProperty("categories");

            foreach (var category in categories.EnumerateObject())
            {
                foreach (var dll in category.Value.EnumerateArray())
                {
                    string? name = dll.GetString();
                    if (name != null) set.Add(name);
                }
            }
        }
        catch (Exception ex)
        {
            // Fallback: return empty set if resource loading fails
            ScanLogger.Debug($"Phantom DLL database could not be loaded: {ex.Message}");
        }
        return set;
    }

    public StaticDiscoveryEngine(ScanProfile profile)
    {
        _profile = profile;
    }

    public List<HijackCandidate> Discover()
    {
        var candidates = new List<HijackCandidate>();

        AnsiConsole.Status().Start("[bold yellow]Static Discovery...[/]", ctx =>
        {
            // ─── Enumerate all execution contexts ───
            ctx.Status("[yellow]Enumerating services...[/]");
            var contexts = new List<DiscoveryContext>();
            contexts.AddRange(ServiceEnumerator.EnumerateServices());

            ctx.Status("[yellow]Enumerating scheduled tasks...[/]");
            contexts.AddRange(ScheduledTaskEnumerator.EnumerateScheduledTasks());

            ctx.Status("[yellow]Enumerating startup items...[/]");
            contexts.AddRange(StartupItemEnumerator.EnumerateStartupItems());

            if (_profile.TriggerCOM)
            {
                ctx.Status("[yellow]Enumerating COM objects...[/]");
                contexts.AddRange(COMEnumerator.EnumerateCOMObjects());
            }

            AnsiConsole.MarkupLine($"  [green]Found {contexts.Count} execution contexts[/]");
            ScanLogger.Debug($"Static discovery: {contexts.Count} execution contexts found");

            if (_profile.TriggerAutoElevate)
            {
                ctx.Status("[yellow]Hunting for AutoElevate UAC Bypass binaries...[/]");
                var autoElevateContexts = AutoElevateEnumerator.EnumerateAutoElevateBinaries();
                contexts.AddRange(autoElevateContexts);
                AnsiConsole.MarkupLine($"  [green]Found {autoElevateContexts.Count} AutoElevate binaries[/]");
            }

            // ═══ FILTER BY TARGET ═══
            if (!string.IsNullOrEmpty(_profile.TargetPath))
            {
                contexts = FilterByTarget(contexts, _profile.TargetPath);
                AnsiConsole.MarkupLine($"  [yellow]Filtered to target: {contexts.Count} contexts match[/]");

                if (contexts.Count == 0)
                {
                    // ═══ DIRECT SCAN FALLBACK ═══
                    // The target file exists on disk but has no registered execution context
                    // (not a service, scheduled task, startup item, or COM object).
                    // Create a synthetic context so the PE analyzer still inspects it.
                    string expandedTarget = Environment.ExpandEnvironmentVariables(_profile.TargetPath);
                    if (File.Exists(expandedTarget))
                    {
                        AnsiConsole.MarkupLine($"  [yellow]⚠ No registered trigger found for this binary. Performing direct PE analysis...[/]");
                        ScanLogger.Debug($"Direct scan fallback: creating synthetic context for {expandedTarget}");
                        contexts.Add(new DiscoveryContext
                        {
                            BinaryPath = Path.GetFullPath(expandedTarget),
                            TriggerType = TriggerType.Manual,
                            TriggerIdentifier = "Direct Scan (no registered trigger)",
                            DisplayName = Path.GetFileName(expandedTarget),
                            RunAsAccount = Native.TokenHelper.GetCurrentUsername(),
                            StartType = "MANUAL",
                            IsAutoStart = false
                        });
                    }
                    else
                    {
                        AnsiConsole.MarkupLine($"[red]No execution contexts found for target: {Markup.Escape(_profile.TargetPath)}[/]");
                        AnsiConsole.MarkupLine($"[dim]Tip: Try using just the filename (e.g., 'app.exe') or a directory path[/]");
                        _lastContexts = new List<DiscoveryContext>();
                        return;
                    }
                }
            }

            // ═══ R4 C: companion executables of services (read-only, always on) ═══
            // After the target filter, so a --target scan covers the companions of the
            // services it matched.
            ctx.Status("[yellow]Looking for service companion executables...[/]");
            var companionReport = new List<CompanionDiscovery.Examined>();
            var companions = CompanionDiscovery.Find(CompanionDiscovery.FromServiceContexts(contexts),
                CompanionDiscovery.Env.Real(), report: companionReport);
            var (cExamined, cKept, cRejected) = CompanionDiscovery.Summarize(companionReport);
            ScanStats.AddCompanions(cExamined, cKept, cRejected);
            ScanLogger.Info($"Companion discovery: examined {cExamined}, kept {cKept}, rejected {cRejected}");
            var registered = new HashSet<string>(contexts.Select(c => c.BinaryPath), StringComparer.OrdinalIgnoreCase);
            var startTypes = contexts.Where(c => c.TriggerType == TriggerType.Service)
                .GroupBy(c => c.TriggerIdentifier, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().StartType, StringComparer.OrdinalIgnoreCase);
            int companionCount = 0;
            foreach (var comp in companions)
            {
                // An EXE that is itself registered (service, task, ...) is analysed as that.
                if (registered.Contains(comp.ExePath))
                {
                    ScanLogger.Debug($"Companion: {comp.ExePath} is also a registered launch point; analysed under that registration");
                    continue;
                }
                contexts.Add(CompanionDiscovery.ToContext(comp,
                    startTypes.TryGetValue(comp.Service, out var st) ? st : "AUTO_START"));
                companionCount++;
                ScanLogger.Debug($"Companion: {comp.ExePath} of service {comp.Service} ({comp.Reason})");
            }
            _lastCompanions = companions;
            if (companionCount > 0)
                AnsiConsole.MarkupLine($"  [green]Found {companionCount} service companion executables in user-writable directories[/]");

            // Store contexts for ETW enrichment later
            _lastContexts = contexts;

            // ─── Deduplicate by binary path ───
            // Ensure we don't drop Phantom COM entries by processing them directly
            var phantomComs = contexts.Where(c => c.TriggerType == TriggerType.COM && !File.Exists(c.BinaryPath)).ToList();
            foreach (var pc in phantomComs)
            {
                candidates.Add(new HijackCandidate
                {
                    BinaryPath = "COM Server", // Represents the logical binary
                    DllName = Path.GetFileName(pc.BinaryPath),
                    DllLegitPath = null,
                    Type = HijackType.Phantom,
                    HijackWritablePath = pc.BinaryPath,
                    Trigger = TriggerType.COM,
                    TriggerIdentifier = pc.TriggerIdentifier,
                    RunAsAccount = pc.RunAsAccount,
                    ServiceStartType = "MANUAL",
                    SurvivesReboot = false,
                    DiscoverySource = "static",
                    Notes = { $"PHANTOM COM: Missing COM server DLL ({pc.DisplayName})" }
                });
            }

            // ═══ NEW: Process AppInit_DLLs directly as targets ═══
            var appInitDlls = contexts.Where(c => c.TriggerIdentifier == "AppInit_DLLs").ToList();
            foreach (var appInit in appInitDlls)
            {
                string? dir = Path.GetDirectoryName(appInit.BinaryPath);
                if (dir != null && Directory.Exists(dir) &&
                    AclChecker.IsDirectoryWritableByStandardUser(dir, appInit.RunAsAccount))
                {
                    candidates.Add(new HijackCandidate
                    {
                        BinaryPath = "User32.dll (AppInit Injection)", // Logical host
                        DllName = Path.GetFileName(appInit.BinaryPath),
                        DllLegitPath = File.Exists(appInit.BinaryPath) ? appInit.BinaryPath : null,
                        Type = HijackType.AppInitDll,
                        HijackWritablePath = appInit.BinaryPath,
                        Trigger = TriggerType.Startup,
                        TriggerIdentifier = appInit.TriggerIdentifier,
                        RunAsAccount = appInit.RunAsAccount,
                        ServiceStartType = "AUTO_START",
                        SurvivesReboot = true,
                        DiscoverySource = "static",
                        Notes = { "AppInit_DLLs registry entry points to a writable DLL path. Modifying this DLL achieves global injection." }
                    });
                }
            }

            // ═══ Process AppCertDlls directly as targets ═══
            // AppCertDLLs load into every process that calls CreateProcess*/WinExec, so a
            // writable referenced DLL yields near-global injection — the same shape as AppInit.
            var appCertDlls = contexts.Where(c => c.TriggerIdentifier == "AppCertDlls").ToList();
            foreach (var appCert in appCertDlls)
            {
                string? dir = Path.GetDirectoryName(appCert.BinaryPath);
                if (dir != null && Directory.Exists(dir) &&
                    AclChecker.IsDirectoryWritableByStandardUser(dir, appCert.RunAsAccount))
                {
                    candidates.Add(new HijackCandidate
                    {
                        BinaryPath = "AppCertDlls (CreateProcess Injection)", // Logical host
                        DllName = Path.GetFileName(appCert.BinaryPath),
                        DllLegitPath = File.Exists(appCert.BinaryPath) ? appCert.BinaryPath : null,
                        Type = HijackType.AppCertDll,
                        HijackWritablePath = appCert.BinaryPath,
                        Trigger = TriggerType.Startup,
                        TriggerIdentifier = appCert.TriggerIdentifier,
                        RunAsAccount = appCert.RunAsAccount,
                        ServiceStartType = "AUTO_START",
                        SurvivesReboot = true,
                        DiscoverySource = "static",
                        Notes = { "AppCertDlls registry entry points to a writable DLL path. Modifying this DLL achieves injection into every process that calls CreateProcess/WinExec." }
                    });
                }
            }

            var uniqueBinaries = contexts
                .Where(c => !(c.TriggerType == TriggerType.COM && !File.Exists(c.BinaryPath)))
                .Where(c => c.TriggerIdentifier != "AppInit_DLLs") // Exclude from PE analysis
                .Where(c => c.TriggerIdentifier != "AppCertDlls")  // Exclude from PE analysis
                .Where(c => File.Exists(c.BinaryPath))
                .GroupBy(c => c.BinaryPath, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

            AnsiConsole.MarkupLine($"  [green]{uniqueBinaries.Count} unique binaries to analyze[/]");
            ScanLogger.Debug($"Static discovery: {uniqueBinaries.Count} unique binaries to analyze");

            if (uniqueBinaries.Count == 0)
            {
                AnsiConsole.MarkupLine($"[yellow]No binaries found to analyze[/]");
                return;
            }

            // ─── Analyze each binary ───
            int analyzed = 0;
            foreach (var (binaryPath, executionContexts) in uniqueBinaries)
            {
                analyzed++;
                if (analyzed % 50 == 0)
                    ctx.Status($"[yellow]Analyzing binary {analyzed}/{uniqueBinaries.Count}...[/]");

                try
                {
                    var peResult = PEAnalyzer.Analyze(binaryPath);
                    if (peResult.AnalysisError != null)
                    {
                        ScanLogger.Debug($"PE analysis skipped {binaryPath}: {peResult.AnalysisError}");
                        continue;
                    }

                    // For each imported DLL, check for hijack opportunities
                    foreach (string dll in peResult.AllImportedDlls)
                    {
                        var dllCandidates = AnalyzeDllImport(
                            binaryPath, dll, executionContexts, peResult);
                        candidates.AddRange(dllCandidates);
                    }

                    // Check for phantom DLLs from our database
                    CheckPhantomDlls(binaryPath, executionContexts, peResult, candidates);
                }
                catch (Exception ex)
                {
                    ScanLogger.Debug($"Static analysis failed for {binaryPath}: {ex.Message}");
                    continue;
                }
            }

            // ─── Check PATH directories for writable entries ───
            // Skip when --target is set: PATH weaponization is system-wide and not meaningful
            // in a targeted scan — the writable dirs are global regardless of target scope.
            if (string.IsNullOrEmpty(_profile.TargetPath))
            {
                ctx.Status("[yellow]Weaponizing writable PATH directories...[/]");
                CheckWritablePathDirectories(candidates, contexts);
            }

            MarkCompanionCandidates(candidates, contexts);

            AnsiConsole.MarkupLine($"  [green]Generated {candidates.Count} candidates[/]");
            ScanLogger.Debug($"Static discovery complete: {candidates.Count} total candidates generated");
        });

        return candidates;
    }

    /// <summary>Whether the loader honours &lt;exe&gt;.local for this binary. TIER 3 rule: no manifest, or DevOverrideEnable=1.</summary>
    internal static bool DotLocalHonoured(bool hasManifest, bool binaryIs64Bit, bool osIs64Bit, bool devOverrideEnable) =>
        !hasManifest || devOverrideEnable;
    // Expose for ETW enrichment
    private List<DiscoveryContext>? _lastContexts;
    public List<DiscoveryContext> GetLastContexts() => _lastContexts ?? new();

    private List<CompanionDiscovery.Companion> _lastCompanions = new();
    /// <summary>Companion executables found by the last Discover() (also those with no finding).</summary>
    internal IReadOnlyList<CompanionDiscovery.Companion> LastCompanions => _lastCompanions;

    /// <summary>Findings on a companion executable carry the companion source, parent and note.</summary>
    internal static void MarkCompanionCandidates(List<HijackCandidate> candidates, List<DiscoveryContext> contexts)
    {
        var companionOf = contexts.Where(c => c.IsCompanion)
            .GroupBy(c => c.BinaryPath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().TriggerIdentifier, StringComparer.OrdinalIgnoreCase);
        foreach (var c in candidates)
        {
            if (!companionOf.TryGetValue(c.BinaryPath, out var svc)) continue;
            c.DiscoverySource = CompanionDiscovery.Source;
            c.CompanionOf = svc;
            string note = CompanionDiscovery.Note(svc);
            if (!c.Notes.Contains(note)) c.Notes.Add(note);
        }
    }

    /// <summary>
    /// Type of a static search-order position: the existing EnvPath rule (a PATH directory that is
    /// not the binary's own directory) first, otherwise the resolver's decision.
    /// </summary>
    internal static HijackType TypeForStaticPosition(bool isPathDirHijack, HijackTypeResolver.Resolution r) =>
        isPathDirHijack ? HijackType.EnvPath : r.Type;

    private List<HijackCandidate> AnalyzeDllImport(string binaryPath, string dllName,
        List<DiscoveryContext> contexts, PEAnalysisResult peResult)
    {
        var candidates = new List<HijackCandidate>();

        // ─── KNOWLEDGE BASE LOOKUP ───
        bool isKnownVuln = KnowledgeBaseEngine.CheckKnowledgeBase(binaryPath, dllName, out string? kbRef);

        // Account the target runs as — also considered when judging writability so a
        // directory writable only by a non-privileged service account still surfaces.
        string bestAccount = contexts.OrderByDescending(c => GetContextPriority(c)).First().RunAsAccount;

        // 1. Normal Search Order Logic
        // R1: the search order of the binary's own architecture (SysWOW64 for 32-bit binaries).
        bool is64 = peResult.Is64Bit;
        var hijackPositions = SearchOrderCalculator.FindHijackablePositions(binaryPath, dllName, bestAccount, is64);
        foreach (var hijackPath in hijackPositions)
        {
            var bestCtx = contexts.OrderByDescending(c => GetContextPriority(c)).First();
            string? legitPath = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName, bestAccount, is64);

            // Reclassify: if the hijack position is in a PATH directory (not the binary's own
            // directory or a system directory), mark as EnvPath so the dedup pass can collapse
            // hundreds of identical (dll, writable-path-dir) findings across many binaries into one.
            string? hijackDir = Path.GetDirectoryName(hijackPath);
            string? binaryDir = Path.GetDirectoryName(binaryPath);
            bool isPathDirHijack = hijackDir != null
                && PathDirSet.Value.Contains(hijackDir)
                && !hijackDir.Equals(binaryDir, StringComparison.OrdinalIgnoreCase);

            // One typing decision (HijackTypeResolver): a real copy later in this binary's order
            // (system directory for its architecture, then the PATH this identity sees) makes the
            // position SearchOrder; none makes it Phantom. The EnvPath rule above still wins.
            var resolution = HijackTypeResolver.Classify(hijackPath, is64,
                SearchOrderCalculator.GetPathDirsFor(bestAccount));

            var candidate = new HijackCandidate
            {
                BinaryPath = binaryPath,
                DllName = dllName,
                DllLegitPath = legitPath ?? resolution.LegitPath,
                Type = TypeForStaticPosition(isPathDirHijack, resolution),
                HijackWritablePath = hijackPath,
                Trigger = bestCtx.TriggerType,
                TriggerIdentifier = bestCtx.TriggerIdentifier,
                RunAsAccount = bestCtx.RunAsAccount,
                ServiceStartType = bestCtx.StartType,
                TaskFrequency = bestCtx.RepeatInterval,
                SurvivesReboot = bestCtx.IsAutoStart,
                DiscoverySource = "static",
                IsKnownVulnerability = isKnownVuln,
                KnowledgeBaseReference = kbRef
            };

            if (!isPathDirHijack) candidate.Notes.Add(resolution.Note);

            if (isKnownVuln)
            {
                candidate.Notes.Add($"[HIJACKLIBS MATCH] Documented vulnerable software detected! Ref: {kbRef}");
            }

            candidates.Add(candidate);
        }
        // Check for .local redirection opportunity
        string dotLocalDir = binaryPath + ".local";
        string dotLocalDllPath = Path.Combine(dotLocalDir, dllName);
        string? dotLocalParent = Path.GetDirectoryName(binaryPath);

        // The loader ignores <exe>.local for any executable with an (embedded or external)
        // manifest unless IFEO DevOverrideEnable=1 is set machine-wide — and nearly every
        // modern EXE carries a manifest. Only emit DotLocal where redirection is honoured.
        bool dotLocalHonoured = DotLocalHonoured(peResult.HasEmbeddedManifest, peResult.Is64Bit,
            Environment.Is64BitOperatingSystem, DevOverrideEnabled.Value);

        if (dotLocalHonoured &&
            dotLocalParent != null &&
            AclChecker.CanCreateSubdirectory(dotLocalParent, bestAccount) &&
            !Directory.Exists(dotLocalDir))
        {
            var bestCtx = contexts.OrderByDescending(c => GetContextPriority(c)).First();
            candidates.Add(new HijackCandidate
            {
                BinaryPath = binaryPath,
                DllName = dllName,
                DllLegitPath = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName, bestAccount, peResult.Is64Bit),
                Type = HijackType.DotLocal,
                HijackWritablePath = dotLocalDllPath,
                Trigger = bestCtx.TriggerType,
                TriggerIdentifier = bestCtx.TriggerIdentifier,
                RunAsAccount = bestCtx.RunAsAccount,
                ServiceStartType = bestCtx.StartType,
                SurvivesReboot = bestCtx.IsAutoStart,
                DiscoverySource = "static",
                IsKnownVulnerability = isKnownVuln,
                KnowledgeBaseReference = kbRef,
                Notes = { "Requires creating .local directory and placing DLL inside" }
            });

            if (isKnownVuln)
            {
                candidates.Last().Notes.Add($"[HIJACKLIBS MATCH] Documented vulnerable software detected! Ref: {kbRef}");
            }
        }

        // ═══ AutoElevate Side-Loading Simulation ═══
        // If this is a UACBypass binary and it doesn't protect against CWD loads,
        // an attacker can copy the EXE to a writable folder (e.g. %TEMP%), place
        // a malicious DLL next to it, and execute for a silent UAC bypass.
        // Skip KnownDLLs and System32-resident DLLs — these cannot be sideloaded.
        // Only a manifest-autoElevate EXE can be copied and launched by the attacker. COM
        // elevation entries (Elevation\Enabled=1) are activated by CLSID from their registered
        // path — and InprocServer32 entries are DLLs, which cannot be "executed" from a copy.
        var uacCtx = contexts.FirstOrDefault(c =>
            c.TriggerType == TriggerType.UACBypass &&
            c.TriggerIdentifier == "Manifest AutoElevate (Heuristic)" &&
            binaryPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
        bool isSideloadBlocked = Filters.KnownDllsFilter.IsKnownDll(dllName) ||
            File.Exists(Path.Combine(Environment.SystemDirectory, dllName));
        if (uacCtx != null && !isSideloadBlocked &&
            !peResult.CallsSetDllDirectory && !peResult.CallsSetDefaultDllDirectories)
        {
            string tempTarget = Path.Combine(Path.GetTempPath(), dllName);
            candidates.Add(new HijackCandidate
            {
                BinaryPath = binaryPath,
                DllName = dllName,
                DllLegitPath = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName),
                Type = HijackType.SideLoad,
                HijackWritablePath = tempTarget,
                Trigger = TriggerType.UACBypass,
                TriggerIdentifier = "Copy-to-Temp Side-Loading",
                RunAsAccount = uacCtx.RunAsAccount,
                ServiceStartType = "MANUAL",
                IsSimulatedCopyAttack = true,
                SurvivesReboot = false,
                DiscoverySource = "static",
                IsKnownVulnerability = isKnownVuln,
                KnowledgeBaseReference = kbRef,
                Notes =
                {
                    "COPY & SIDE-LOAD: Attacker copies this AutoElevate EXE next to a planted DLL " +
                    "and executes it for a silent UAC bypass. Auto-elevation is only granted from " +
                    "a trusted directory, so the copy must pass that check (e.g. a mock " +
                    "'C:\\Windows \\System32\\' folder); a plain %TEMP% copy will show a UAC prompt."
                }
            });

            if (isKnownVuln)
            {
                candidates.Last().Notes.Add($"[HIJACKLIBS MATCH] Documented vulnerable software detected! Ref: {kbRef}");
            }
        }

        return candidates;
    }

    private void CheckPhantomDlls(string binaryPath, List<DiscoveryContext> contexts,
        PEAnalysisResult peResult, List<HijackCandidate> candidates)
    {
        string bestAccount = contexts.OrderByDescending(c => GetContextPriority(c)).First().RunAsAccount;

        foreach (string dll in peResult.AllImportedDlls)
        {
            if (!PhantomDllDatabase.Value.Contains(dll)) continue;

            string? actualLocation = SearchOrderCalculator.FindActualDllLocation(binaryPath, dll, bestAccount, peResult.Is64Bit);
            if (actualLocation != null) continue;

            string? binaryDir = Path.GetDirectoryName(binaryPath);
            if (binaryDir != null && AclChecker.IsDirectoryWritableByStandardUser(binaryDir, bestAccount))
            {
                var bestCtx = contexts.OrderByDescending(c => GetContextPriority(c)).First();
                string writablePath = Path.Combine(binaryDir, dll);

                // Reclassify PATH-directory positions as EnvPath for cross-binary dedup.
                bool isPathDir = PathDirSet.Value.Contains(binaryDir);

                // R1: the same typing decision as every other site. FindActualDllLocation above
                // already found no copy in this binary's order, so this is Phantom unless the
                // resolver sees a copy it does not (it never does today; kept as one decision).
                var resolution = HijackTypeResolver.Classify(writablePath, peResult.Is64Bit,
                    SearchOrderCalculator.GetPathDirsFor(bestAccount));

                var phantom = new HijackCandidate
                {
                    BinaryPath = binaryPath,
                    DllName = dll,
                    DllLegitPath = resolution.LegitPath,
                    Type = TypeForStaticPosition(isPathDir, resolution),
                    HijackWritablePath = writablePath,
                    Trigger = bestCtx.TriggerType,
                    TriggerIdentifier = bestCtx.TriggerIdentifier,
                    RunAsAccount = bestCtx.RunAsAccount,
                    ServiceStartType = bestCtx.StartType,
                    SurvivesReboot = bestCtx.IsAutoStart,
                    DiscoverySource = "static"
                };
                if (!isPathDir) phantom.Notes.Add(resolution.Note);
                candidates.Add(phantom);
            }
        }
    }

    private void CheckWritablePathDirectories(List<HijackCandidate> candidates, List<DiscoveryContext> contexts)
    {
        // Every global target below is a service. A service account only ever searches the
        // MACHINE PATH, so a writable directory that exists only in the scanning user's
        // per-user PATH (e.g. C:\Python311) is not reachable by these services. Collect the
        // writable directories from the union, then check per target against the PATH that
        // the target's own identity actually sees.
        var processPath = SearchOrderCalculator.GetPathDirsFor(null) ?? Array.Empty<string>();
        var machinePath = SearchOrderCalculator.GetPathDirsFor("NT AUTHORITY\\SYSTEM") ?? Array.Empty<string>();

        var writablePaths = new List<string>();
        foreach (var dir in processPath.Concat(machinePath).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(dir)) continue;
            if (Native.AclChecker.IsDirectoryWritableByStandardUser(dir)) writablePaths.Add(dir);
        }

        if (writablePaths.Any())
        {
            AnsiConsole.MarkupLine($"  [yellow]⚠ {writablePaths.Count} writable PATH directories found. Initializing Automated Exploit Engine...[/]");
            
            // These are notorious Phantom DLLs that native Windows services constantly poll for.
            // If they are missing from System32, the OS falls back to searching the PATH.
            var globalTargets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "wlbsctrl.dll", "IKEEXT" },        // IKE and AuthIP IPsec Keying Modules
                { "tsmsisrv.dll", "SessionEnv" },    // Remote Desktop Configuration
                { "ualapi.dll", "Spooler" },         // Print Spooler
                { "wlanhlp.dll", "WlanSvc" },        // WLAN AutoConfig
                { "WptsExtensions.dll", "Schedule" } // Task Scheduler
            };

            foreach (var wp in writablePaths)
            {
                AnsiConsole.MarkupLine($"    [red]• Weaponizing PATH: {Markup.Escape(wp)}[/]");
                
                foreach (var target in globalTargets)
                {
                    // Find the context for the native service so the Canary Engine can trigger it
                    var svcCtx = contexts.FirstOrDefault(c => 
                        c.TriggerType == TriggerType.Service && 
                        c.TriggerIdentifier.Equals(target.Value, StringComparison.OrdinalIgnoreCase));

                    // Skip PATH entries this service's identity never searches.
                    if (svcCtx != null)
                    {
                        var targetPath = SearchOrderCalculator.GetPathDirsFor(svcCtx.RunAsAccount);
                        if (targetPath == null ||
                            !targetPath.Contains(wp, StringComparer.OrdinalIgnoreCase))
                        {
                            ScanLogger.Debug($"PATH weaponization: {wp} is not in the PATH seen by " +
                                $"{svcCtx.TriggerIdentifier} ({svcCtx.RunAsAccount}) — skipped");
                            continue;
                        }

                        candidates.Add(new HijackCandidate
                        {
                            BinaryPath = svcCtx.BinaryPath,
                            DllName = target.Key,
                            DllLegitPath = null, // It's a Phantom DLL
                            Type = HijackType.EnvPath,
                            HijackWritablePath = Path.Combine(wp, target.Key),
                            Trigger = TriggerType.Service,
                            TriggerIdentifier = svcCtx.TriggerIdentifier,
                            RunAsAccount = svcCtx.RunAsAccount,
                            ServiceStartType = svcCtx.StartType,
                            SurvivesReboot = svcCtx.IsAutoStart,
                            DiscoverySource = "static",
                            IsKnownVulnerability = true,
                            KnowledgeBaseReference = "https://hijacklibs.net/",
                            Notes = { $"GLOBAL PATH WEAPONIZATION: Service '{target.Value}' may dynamically poll for {target.Key}. Dropping it in writable PATH ({wp}) is a strong system-wide hijack vector." }
                        });
                        
                        candidates.Last().Notes.Add($"[HIJACKLIBS MATCH] Documented System-Wide PATH Hijack Strategy Detected! Ref: https://hijacklibs.net/");
                    }
                }
            }
        }
    }
    // ═══ FILTER BY TARGET ═══
    private static List<DiscoveryContext> FilterByTarget(List<DiscoveryContext> contexts, string target)
    {
        // Expand environment variables in target
        string expandedTarget = Environment.ExpandEnvironmentVariables(target);

        // Normalize path separators (D:/vlc.exe → D:\vlc.exe)
        expandedTarget = expandedTarget.Replace('/', Path.DirectorySeparatorChar);

        // Check if target is a directory or file
        bool isDirectory = Directory.Exists(expandedTarget);
        bool isFile = File.Exists(expandedTarget);

        if (isFile)
        {
            // Try full path normalization for exact match
            string fullPath = Path.GetFullPath(expandedTarget);

            // 1. Exact file path match
            var exactMatches = contexts.Where(c =>
                c.BinaryPath.Equals(fullPath, StringComparison.OrdinalIgnoreCase) ||
                c.BinaryPath.Equals(expandedTarget, StringComparison.OrdinalIgnoreCase)
            ).ToList();

            if (exactMatches.Any())
            {
                AnsiConsole.MarkupLine($"  [green]✓ Found exact match for: {Markup.Escape(fullPath)}[/]");
                return exactMatches;
            }

            // 2. Filename-only match: user passed "D:\vlc.exe" → find any context with "vlc.exe"
            //    This handles the case where the binary is registered at a different path
            //    (e.g., C:\Program Files\VideoLAN\VLC\vlc.exe)
            string targetFileName = Path.GetFileName(expandedTarget);
            var filenameMatches = contexts.Where(c =>
                Path.GetFileName(c.BinaryPath).Equals(targetFileName, StringComparison.OrdinalIgnoreCase)
            ).ToList();

            if (filenameMatches.Any())
            {
                AnsiConsole.MarkupLine($"  [green]✓ Found {filenameMatches.Count} registered contexts matching filename: {Markup.Escape(targetFileName)}[/]");
                foreach (var match in filenameMatches.Take(5))
                    AnsiConsole.MarkupLine($"    [dim]• {Markup.Escape(match.BinaryPath)} ({match.TriggerType})[/]");
                if (filenameMatches.Count > 5)
                    AnsiConsole.MarkupLine($"    [dim]... and {filenameMatches.Count - 5} more[/]");
                return filenameMatches;
            }

            // 3. No context matches at all — return empty so the caller can do direct scan
            ScanLogger.Debug($"FilterByTarget: file '{fullPath}' exists but has no matching execution context");
            return new List<DiscoveryContext>();
        }

        if (isDirectory)
        {
            // Directory - match anything under it (ensure trailing separator to avoid partial matches)
            string dirPrefix = expandedTarget.EndsWith(Path.DirectorySeparatorChar)
                ? expandedTarget : expandedTarget + Path.DirectorySeparatorChar;
            var dirMatches = contexts.Where(c =>
                c.BinaryPath.StartsWith(dirPrefix, StringComparison.OrdinalIgnoreCase) ||
                Path.GetDirectoryName(c.BinaryPath)?.Equals(expandedTarget, StringComparison.OrdinalIgnoreCase) == true
            ).ToList();

            if (dirMatches.Any())
            {
                AnsiConsole.MarkupLine($"  [green]✓ Found {dirMatches.Count} binaries in: {Markup.Escape(expandedTarget)}[/]");
                return dirMatches;
            }
        }

        // Partial match (filename or path fragment) — for inputs like "VLC", "notepad", etc.
        string targetLower = target.ToLowerInvariant();
        var partialMatches = contexts.Where(c =>
        {
            string pathLower = c.BinaryPath.ToLowerInvariant();
            string filenameLower = Path.GetFileName(c.BinaryPath).ToLowerInvariant();
            string fileNameNoExtLower = Path.GetFileNameWithoutExtension(c.BinaryPath).ToLowerInvariant();

            return pathLower.Contains(targetLower) ||
                   filenameLower.Contains(targetLower) ||
                   filenameLower.Equals(targetLower, StringComparison.OrdinalIgnoreCase) ||
                   fileNameNoExtLower.Equals(targetLower, StringComparison.OrdinalIgnoreCase);
        }).ToList();

        if (partialMatches.Any())
        {
            AnsiConsole.MarkupLine($"  [green]✓ Found {partialMatches.Count} binaries matching: {Markup.Escape(target)}[/]");
            
            // Show first few matches
            if (partialMatches.Count <= 5)
            {
                foreach (var match in partialMatches)
                    AnsiConsole.MarkupLine($"    [dim]• {Markup.Escape(match.BinaryPath)} ({match.TriggerType})[/]");
            }
            else
            {
                foreach (var match in partialMatches.Take(3))
                    AnsiConsole.MarkupLine($"    [dim]• {Markup.Escape(match.BinaryPath)} ({match.TriggerType})[/]");
                AnsiConsole.MarkupLine($"    [dim]... and {partialMatches.Count - 3} more[/]");
            }
        }

        return partialMatches;
    }

    private static int GetContextPriority(DiscoveryContext ctx) => ctx.TriggerType switch
    {
        TriggerType.Service when ctx.IsAutoStart => 10,
        TriggerType.Service => 8,
        TriggerType.UACBypass => 8,
        TriggerType.ScheduledTask when ctx.IsAutoStart => 7,
        TriggerType.ScheduledTask => 6,
        TriggerType.Startup => 5,
        TriggerType.RunKey => 4,
        TriggerType.COM => 3,
        _ => 1
    };
}