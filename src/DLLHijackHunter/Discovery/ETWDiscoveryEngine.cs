using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Spectre.Console;
using System.Collections.Concurrent;
using DLLHijackHunter.Safety;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("DLLHijackHunter.Tests")]

namespace DLLHijackHunter.Discovery;

public class ETWDiscoveryEngine
{
    private readonly ScanProfile _profile;
    private readonly ConcurrentDictionary<int, DiscoveryContext> _processes = new();
    private readonly ConcurrentBag<HijackCandidate> _candidates = new();
    private readonly ConcurrentDictionary<string, byte> _failedLookups = new();
    private readonly EtwEnvironment _env;

    public ETWDiscoveryEngine(ScanProfile profile) : this(profile, new EtwEnvironment()) { }

    /// <summary>Test seam: every machine query the event handlers make goes through <paramref name="env"/>.</summary>
    internal ETWDiscoveryEngine(ScanProfile profile, EtwEnvironment env)
    {
        _profile = profile;
        _env = env;
    }

    /// <summary>Candidates created so far (tests read this instead of running a trace).</summary>
    internal IReadOnlyList<HijackCandidate> Candidates => _candidates.ToList();

    public async Task<List<HijackCandidate>> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        if (!(TraceEventSession.IsElevated() ?? false))
        {
            AnsiConsole.MarkupLine("[red]ETW requires elevation. Skipping runtime discovery.[/]");
            return new List<HijackCandidate>();
        }

        // Kill any leftover session from previous run
        try
        {
            var existingSession = TraceEventSession.GetActiveSession("DLLHijackHunter-Trace");
            existingSession?.Stop();
            existingSession?.Dispose();
        }
        catch { }

        AnsiConsole.MarkupLine("[yellow]Starting ETW runtime discovery...[/]");

        using var session = new TraceEventSession("DLLHijackHunter-Trace");

        try
        {
            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO
            );

            // Kernel ProcessStart only fires for processes created after the session starts;
            // seed the table with already-running processes so their image loads and failed
            // lookups can still be attributed.
            SeedRunningProcesses();

            session.Source.Kernel.ProcessStart += OnProcessStart;
            session.Source.Kernel.ImageLoad += OnImageLoad;
            session.Source.Kernel.FileIOCreate += OnFileIOCreate;

            var processingTask = Task.Run(() =>
            {
                try { session.Source.Process(); }
                catch { /* session stopped */ }
            });

            await AnsiConsole.Status().StartAsync("[bold yellow]ETW Tracing...[/]", async ctx =>
            {
                if (_profile.TriggerServices)
                {
                    ctx.Status("[yellow]Triggering services...[/]");
                    await TriggerServices();
                }

                if (_profile.TriggerScheduledTasks)
                {
                    ctx.Status("[yellow]Triggering scheduled tasks...[/]");
                    await TriggerScheduledTasks();
                }

                ctx.Status($"[yellow]Collecting ETW events for {_profile.ETWDurationSeconds}s...[/]");
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(_profile.ETWDurationSeconds), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    AnsiConsole.MarkupLine("[yellow]ETW collection cancelled.[/]");
                }
            });

            session.Stop();
            AnsiConsole.MarkupLine($"  [green]ETW captured {_candidates.Count} candidates, " +
                $"{_failedLookups.Count} failed DLL lookups[/]");
            ScanLogger.Debug($"ETW results: {_candidates.Count} candidates, {_failedLookups.Count} failed DLL lookups");
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]ETW error: {Markup.Escape(ex.Message)}[/]");
            ScanLogger.Debug($"ETW error: {ex}");
            try { session.Stop(); } catch { }
        }

        return _candidates.ToList();
    }

    /// <summary>
    /// Enrich ETW candidates with static context data (RunAsAccount, Trigger, etc.)
    /// </summary>
    public void EnrichWithStaticData(List<HijackCandidate> etwCandidates,
        List<DiscoveryContext> staticContexts)
    {
        var contextByPath = staticContexts
            .GroupBy(c => c.BinaryPath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(c => GetPriority(c)).First(),
                StringComparer.OrdinalIgnoreCase);

        var contextByName = staticContexts
            .GroupBy(c => Path.GetFileName(c.BinaryPath).ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.OrderByDescending(c => GetPriority(c)).First(),
                StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in etwCandidates)
        {
            DiscoveryContext? ctx = null;

            // Try exact path match first
            if (!string.IsNullOrEmpty(candidate.BinaryPath))
                contextByPath.TryGetValue(candidate.BinaryPath, out ctx);

            // Fall back to filename match
            if (ctx == null && !string.IsNullOrEmpty(candidate.BinaryPath))
            {
                string name = Path.GetFileName(candidate.BinaryPath).ToLowerInvariant();
                contextByName.TryGetValue(name, out ctx);
            }

            if (ctx != null)
            {
                if (string.IsNullOrEmpty(candidate.RunAsAccount) || candidate.RunAsAccount == "Unknown")
                    candidate.RunAsAccount = ctx.RunAsAccount;
                if (candidate.Trigger == TriggerType.Unknown)
                {
                    candidate.Trigger = ctx.TriggerType;
                    candidate.TriggerIdentifier = ctx.TriggerIdentifier;
                }
                if (string.IsNullOrEmpty(candidate.ServiceStartType))
                    candidate.ServiceStartType = ctx.StartType;
                candidate.SurvivesReboot = ctx.IsAutoStart;
                continue;
            }

            // No static context for the candidate's own binary: fall back to the static context
            // of the process that spawned it (e.g. a service launching a helper exe). Only fills
            // fields that are still empty/Unknown.
            string? parentPath = GetParentBinaryPathFromNotes(candidate);
            if (string.IsNullOrEmpty(parentPath) || IsInheritanceBoundary(parentPath)) continue;

            if (!contextByPath.TryGetValue(parentPath, out var parentCtx))
                contextByName.TryGetValue(Path.GetFileName(parentPath).ToLowerInvariant(), out parentCtx);
            if (parentCtx == null) continue;

            bool inherited = false;
            if (candidate.Trigger == TriggerType.Unknown && parentCtx.TriggerType != TriggerType.Unknown)
            {
                candidate.Trigger = parentCtx.TriggerType;
                if (string.IsNullOrEmpty(candidate.TriggerIdentifier))
                    candidate.TriggerIdentifier = parentCtx.TriggerIdentifier;
                inherited = true;
            }
            if ((string.IsNullOrEmpty(candidate.RunAsAccount) || candidate.RunAsAccount == "Unknown") &&
                !string.IsNullOrEmpty(parentCtx.RunAsAccount))
            {
                candidate.RunAsAccount = parentCtx.RunAsAccount;
                inherited = true;
            }
            if (string.IsNullOrEmpty(candidate.ServiceStartType) && !string.IsNullOrEmpty(parentCtx.StartType))
            {
                candidate.ServiceStartType = parentCtx.StartType;
                inherited = true;
            }
            if (!candidate.SurvivesReboot && parentCtx.IsAutoStart)
            {
                candidate.SurvivesReboot = true;
                inherited = true;
            }

            if (inherited)
            {
                candidate.Notes.Add($"Trigger inherited from parent process {parentPath}");
                ScanLogger.Debug($"ETW enrich: {candidate.BinaryPath} -> {candidate.DllName} inherited " +
                    $"{candidate.Trigger}:{candidate.TriggerIdentifier} from parent {parentPath}");
            }
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            HandleProcessStart(data.ProcessID, data.ParentID, data.ImageFileName ?? "", data.CommandLine ?? "");
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"ETW ProcessStart handling failed (PID {data.ProcessID}): {ex.Message}");
        }
    }

    internal void HandleProcessStart(int pid, int parentPid, string imageFileName, string commandLine)
    {
        // ImageFileName in the kernel event is only the short image name ("svchost.exe"),
        // not a path. Resolve the full Win32 path from the live process; fall back to the
        // short name only if the process has already exited.
        string fullPath = _env.QueryImagePath(pid) ?? imageFileName;
        var ctx = BuildContext(pid, fullPath, commandLine);
        ctx.ParentPid = parentPid;
        TrackProcess(ctx);
    }

    /// <summary>Record an already-running process (used by the seed pass and by tests).</summary>
    internal bool SeedProcess(int pid, int parentPid, string path)
    {
        var ctx = BuildContext(pid, path, "");
        ctx.ParentPid = parentPid;
        return _processes.TryAdd(pid, ctx);
    }

    /// <summary>Link seeded processes to their parents once all are known.</summary>
    internal void LinkSeeded()
    {
        foreach (var ctx in _processes.Values)
            if (ctx.ParentPid > 0) LinkToParent(ctx);
    }

    private void SeedRunningProcesses()
    {
        try
        {
            var startTimes = new Dictionary<int, DateTime>();
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                using (p)
                {
                    string? path = _env.QueryImagePath(p.Id);
                    if (path == null) continue;
                    if (SeedProcess(p.Id, TryGetParentPid(p.Id), path))
                        try { startTimes[p.Id] = p.StartTime; } catch { }
                }
            }

            // Second pass, once every seeded process is known: link parents. A parent PID whose
            // current owner started after the child is a reused PID, not the real parent.
            foreach (var ctx in _processes.Values)
            {
                if (ctx.ParentPid <= 0) continue;
                if (startTimes.TryGetValue(ctx.Pid, out var childStart) &&
                    startTimes.TryGetValue(ctx.ParentPid, out var parentStart) &&
                    parentStart > childStart)
                {
                    ctx.ParentPid = 0;
                    continue;
                }
                LinkToParent(ctx);
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"ETW: could not seed running processes: {ex.Message}");
        }
    }

    private DiscoveryContext BuildContext(int pid, string binaryPath, string commandLine)
    {
        var ctx = new DiscoveryContext
        {
            Pid = pid,
            BinaryPath = binaryPath,
            CommandLine = commandLine,
            TokenUser = "Unknown",
            IntegrityLevel = "Unknown"
        };

        // Protected / exited / access denied: identity stays "Unknown" and is filled from
        // static context data by EnrichWithStaticData where possible.
        if (_env.QueryToken(pid) is (string user, string integrity))
        {
            ctx.TokenUser = user;
            ctx.IntegrityLevel = integrity;
        }

        return ctx;
    }

    internal static (string user, string integrity)? QueryProcessToken(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            return (TokenHelper.GetProcessUser(proc.Handle), TokenHelper.GetProcessIntegrityLevel(proc.Handle));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parent PID via NtQueryInformationProcess(ProcessBasicInformation).
    /// PROCESS_BASIC_INFORMATION = 6 pointer-sized fields; InheritedFromUniqueProcessId is the last.
    /// </summary>
    private static int TryGetParentPid(int pid)
    {
        IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return 0;
        int size = IntPtr.Size * 6;
        IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try
        {
            int status = NativeMethods.NtQueryInformationProcess(h, 0 /* ProcessBasicInformation */, buf, size, out _);
            return status == 0
                ? (int)System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, IntPtr.Size * 5)
                : 0;
        }
        catch { return 0; }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
            NativeMethods.CloseHandle(h);
        }
    }

    internal static string? TryGetFullImagePath(int pid)
    {
        IntPtr h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new System.Text.StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            return NativeMethods.QueryFullProcessImageNameW(h, 0, sb, ref size) && size > 0
                ? sb.ToString()
                : null;
        }
        finally
        {
            NativeMethods.CloseHandle(h);
        }
    }

    /// <summary>
    /// Same target semantics as static discovery: a full file path, a directory (anything
    /// beneath it), or a bare file name / name fragment.
    /// </summary>
    private bool MatchesTarget(string binaryPath)
    {
        if (string.IsNullOrEmpty(_profile.TargetPath)) return true;
        if (string.IsNullOrEmpty(binaryPath)) return false;

        string target = Environment.ExpandEnvironmentVariables(_profile.TargetPath)
            .Replace('/', Path.DirectorySeparatorChar)
            .TrimEnd(Path.DirectorySeparatorChar);

        if (binaryPath.Equals(target, StringComparison.OrdinalIgnoreCase)) return true;
        if (binaryPath.StartsWith(target + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return true;

        string fileName = Path.GetFileName(binaryPath);
        string targetName = Path.GetFileName(target);
        return fileName.Equals(targetName, StringComparison.OrdinalIgnoreCase) ||
               Path.GetFileNameWithoutExtension(fileName).Equals(targetName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A process is in scope when its own binary matches --target, or when it was spawned by a
    /// binary that does (e.g. a service under the target dir launching a helper elsewhere).
    /// </summary>
    internal bool MatchesTarget(DiscoveryContext ctx) =>
        MatchesTarget(ctx.BinaryPath) ||
        (!string.IsNullOrEmpty(ctx.ParentBinaryPath) && MatchesTarget(ctx.ParentBinaryPath));

    /// <summary>
    /// Whether a failed DLL lookup should become a candidate. With --target set, a lookup from an
    /// untracked process (e.g. PID 4 / System doing filesystem work, or a process that exited
    /// before its path was read) cannot be shown to be in scope, so it is dropped.
    /// </summary>
    internal bool ShouldAttributeLookup(DiscoveryContext? ctx) =>
        ctx != null ? MatchesTarget(ctx) : string.IsNullOrEmpty(_profile.TargetPath);

    // ─── Parent / child context inheritance ───

    /// <summary>Note carried on ETW candidates so EnrichWithStaticData can find the parent.</summary>
    internal const string ParentNotePrefix = "Spawned by parent process ";
    private const int MaxAncestorWalk = 3;

    // Processes that launch arbitrary, unrelated children. Inheritance never crosses them.
    private static readonly HashSet<string> InheritanceBoundaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "services.exe", "svchost.exe", "explorer.exe"
    };

    private static bool IsInheritanceBoundary(string binaryPath) =>
        !string.IsNullOrEmpty(binaryPath) && InheritanceBoundaries.Contains(Path.GetFileName(binaryPath));

    /// <summary>
    /// Record a process and link it to its parent (ctx.ParentPid). If an ancestor within
    /// <see cref="MaxAncestorWalk"/> hops has a known trigger, copy it onto the child. The walk
    /// stops at services.exe / svchost.exe / explorer.exe.
    /// </summary>
    internal void TrackProcess(DiscoveryContext ctx)
    {
        LinkToParent(ctx);
        _processes[ctx.Pid] = ctx;
    }

    private void LinkToParent(DiscoveryContext ctx)
    {
        if (ctx.ParentPid <= 0 || ctx.ParentPid == ctx.Pid) return;
        if (!_processes.TryGetValue(ctx.ParentPid, out var parent)) return;

        ctx.ParentBinaryPath = parent.BinaryPath;
        if (ctx.TriggerType != TriggerType.Unknown) return;

        var visited = new HashSet<int> { ctx.Pid };
        var ancestor = parent;
        for (int hop = 0; hop < MaxAncestorWalk && ancestor != null; hop++)
        {
            if (!visited.Add(ancestor.Pid) || IsInheritanceBoundary(ancestor.BinaryPath)) return;

            if (ancestor.TriggerType != TriggerType.Unknown)
            {
                ctx.TriggerType = ancestor.TriggerType;
                ctx.TriggerIdentifier = ancestor.TriggerIdentifier;
                ctx.IsAutoStart = ancestor.IsAutoStart;
                ctx.StartType = ancestor.StartType;
                ctx.RunAsAccount = ancestor.RunAsAccount;
                ScanLogger.Debug($"ETW: PID {ctx.Pid} ({ctx.BinaryPath}) inherited trigger " +
                    $"{ctx.TriggerType}:{ctx.TriggerIdentifier} from PID {ancestor.Pid} ({ancestor.BinaryPath})");
                return;
            }

            ancestor = ancestor.ParentPid > 0 && _processes.TryGetValue(ancestor.ParentPid, out var next)
                ? next : null;
        }
    }

    /// <summary>Copy runtime/inherited context onto a freshly created ETW candidate.</summary>
    private static void ApplyProcessContext(HijackCandidate candidate, DiscoveryContext ctx)
    {
        if (ctx.TriggerType != TriggerType.Unknown)
        {
            candidate.Trigger = ctx.TriggerType;
            candidate.TriggerIdentifier = ctx.TriggerIdentifier;
            if (!string.IsNullOrEmpty(ctx.StartType)) candidate.ServiceStartType = ctx.StartType;
            candidate.SurvivesReboot = ctx.IsAutoStart;
        }
        if ((string.IsNullOrEmpty(candidate.RunAsAccount) || candidate.RunAsAccount == "Unknown") &&
            !string.IsNullOrEmpty(ctx.RunAsAccount))
            candidate.RunAsAccount = ctx.RunAsAccount;
        if (!string.IsNullOrEmpty(ctx.ParentBinaryPath))
            candidate.Notes.Add(ParentNotePrefix + ctx.ParentBinaryPath);
    }

    /// <summary>
    /// The copy of <paramref name="dllName"/> the loader would fall through to after the probed
    /// app-dir position: System32 for a 64-bit process, SysWOW64 for a 32-bit one. Null when
    /// the DLL exists in neither (a true phantom).
    /// </summary>
    internal static string? ResolveSystemCopy(string dllName, bool processIs64Bit)
    {
        if (string.IsNullOrEmpty(dllName) || dllName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            return null;
        string dir = processIs64Bit || !Environment.Is64BitOperatingSystem
            ? Environment.SystemDirectory
            : Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        if (string.IsNullOrEmpty(dir)) return null;
        string path = Path.Combine(dir, dllName);
        return File.Exists(path) ? path : null;
    }

    private readonly ConcurrentDictionary<string, bool> _is64BitByBinary = new(StringComparer.OrdinalIgnoreCase);

    private bool? IsBinary64Bit(string binaryPath)
    {
        if (string.IsNullOrEmpty(binaryPath) || !Path.IsPathRooted(binaryPath)) return null;
        if (_env.Is64Bit != null) return _env.Is64Bit(binaryPath);
        if (_is64BitByBinary.TryGetValue(binaryPath, out bool cached)) return cached;
        try
        {
            bool is64 = PEAnalyzer.Analyze(binaryPath).Is64Bit;
            _is64BitByBinary[binaryPath] = is64;
            return is64;
        }
        catch { return null; }
    }

    private static string? GetParentBinaryPathFromNotes(HijackCandidate candidate)
    {
        string? note = candidate.Notes.FirstOrDefault(n => n.StartsWith(ParentNotePrefix, StringComparison.Ordinal));
        return note?[ParentNotePrefix.Length..].Trim();
    }

    private void OnImageLoad(ImageLoadTraceData data)
    {
        try { HandleImageLoad(data.ProcessID, data.FileName ?? ""); }
        catch { }
    }

    internal void HandleImageLoad(int pid, string fileName)
    {
        {
            if (!fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;

            if (_processes.TryGetValue(pid, out var ctx))
            {
                // When --target is set, skip processes whose binary (or parent's) is not under the target.
                if (!MatchesTarget(ctx)) return;

                ctx.LoadedDlls.Add(fileName);

                string dllName = Path.GetFileName(fileName);
                string? actualDir = Path.GetDirectoryName(fileName);
                string? binaryDir = Path.GetDirectoryName(ctx.BinaryPath);

                if (actualDir == null) return;

                // Skip DLLs loaded from the binary's own directory — this is the
                // expected/intended load location, not a search-order hijack.
                if (binaryDir != null &&
                    actualDir.Equals(binaryDir, StringComparison.OrdinalIgnoreCase))
                    return;

                // Skip system directories (use normalized path comparison)
                string sysDir = Environment.SystemDirectory;
                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (actualDir.Equals(sysDir, StringComparison.OrdinalIgnoreCase) ||
                    actualDir.Equals(winDir, StringComparison.OrdinalIgnoreCase) ||
                    actualDir.StartsWith(sysDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                    actualDir.StartsWith(winDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    return;

                if (_env.IsDirWritable(actualDir))
                {
                    var candidate = new HijackCandidate
                    {
                        BinaryPath = ctx.BinaryPath,
                        DllName = dllName,
                        DllLegitPath = fileName,
                        Type = HijackType.SearchOrder,
                        HijackWritablePath = Path.Combine(actualDir, dllName),
                        RunAsAccount = ctx.TokenUser,
                        DiscoverySource = "etw",
                        Notes = {
                            $"DLL loaded from writable directory at runtime (PID {pid})",
                            "[HEURISTIC] ETW cannot guarantee load priority. Verify search-order precedence manually or via Canary."
                        }
                    };
                    ApplyProcessContext(candidate, ctx);
                    _candidates.Add(candidate);
                }
            }
        }
    }

    private void OnFileIOCreate(FileIOCreateTraceData data)
    {
        try { HandleFileIOCreate(data.ProcessID, data.FileName ?? ""); }
        catch { }
    }

    internal void HandleFileIOCreate(int pid, string fileName)
    {
        {
            if (!fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;

            if (!_env.FileExists(fileName))
            {
                string lookupKey = $"{pid}|{fileName}";
                if (_failedLookups.TryAdd(lookupKey, 0))
                {
                    string? dir = Path.GetDirectoryName(fileName);
                    if (dir != null && _env.DirectoryExists(dir) &&
                        _env.IsDirWritable(dir))
                    {
                        string dllName = Path.GetFileName(fileName);
                        string processPath = "";
                        string tokenUser = "Unknown";

                        _processes.TryGetValue(pid, out var ctx);
                        if (!ShouldAttributeLookup(ctx)) return;

                        if (ctx != null)
                        {
                            processPath = ctx.BinaryPath;
                            tokenUser = ctx.TokenUser;
                            ctx.FailedDllLookups.Add(fileName);
                        }

                        var candidate = new HijackCandidate
                        {
                            BinaryPath = processPath,
                            DllName = dllName,
                            DllLegitPath = null,
                            Type = HijackType.Phantom,
                            HijackWritablePath = fileName,
                            RunAsAccount = tokenUser,
                            DiscoverySource = "etw",
                            Notes =
                            {
                                $"Phantom DLL detected via ETW (PID {pid})",
                                $"Process probed {fileName} but file does not exist",
                                "[HEURISTIC] ETW cannot guarantee load priority. Verify search-order precedence manually or via Canary."
                            }
                        };
                        if (ctx != null) ApplyProcessContext(candidate, ctx);

                        // The probed path is missing, but the DLL may exist in the system dir the
                        // loader falls through to (app dir is searched first). Record that copy so
                        // the canary is built as an export-forwarding proxy: a static importer
                        // cannot finish loading an export-less canary, so DllMain would never run.
                        if (IsBinary64Bit(processPath) is bool is64 &&
                            ResolveSystemCopy(dllName, is64) is string systemCopy)
                        {
                            candidate.DllLegitPath = systemCopy;
                            candidate.Notes.Add($"Real copy loads from {systemCopy}; the writable app-dir " +
                                "position is probed first (canary will forward its exports)");
                        }

                        _candidates.Add(candidate);
                    }
                }
            }
        }
    }

    private async Task TriggerServices()
    {
        try
        {
            var services = ServiceEnumerator.EnumerateServices()
                .Where(s => s.IsAutoStart && s.StartType != "DISABLED")
                // When --target is set, only trigger services whose binary matches the target.
                .Where(s => MatchesTarget(s.BinaryPath))
                .GroupBy(s => s.TriggerIdentifier)
                .Select(g => g.First())
                .Take(100)
                .ToList();

            // A service that is already running loaded its DLLs (and spawned its children) before
            // the ETW session existed, so `sc start` alone shows nothing. With a --target scope,
            // restart the matching running services so their startup happens under the trace.
            bool targetSet = !string.IsNullOrEmpty(_profile.TargetPath);
            var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (targetSet)
            {
                foreach (var svc in services)
                    if (IsRunningState(await RunScAsync($"query \"{svc.TriggerIdentifier}\"", 5000)))
                        running.Add(svc.TriggerIdentifier);
            }

            var plan = PlanServiceTriggers(services.Select(s => s.TriggerIdentifier), targetSet, running,
                ServiceControl.Guard, out bool capExceeded);
            if (capExceeded)
            {
                AnsiConsole.MarkupLine($"[yellow]  {running.Count} matching services are already running; not restarting " +
                    $"more than {MaxServiceRestarts}. Narrow --target, or stop the service before scanning.[/]");
                ScanLogger.Debug($"ETW: {running.Count} running target services exceed restart cap {MaxServiceRestarts}; start-only");
            }

            foreach (var step in plan)
            {
                try
                {
                    if (step.Stop)
                    {
                        ScanLogger.Debug($"ETW: restarting running target service '{step.Service}' under trace");
                        AnsiConsole.MarkupLine($"[yellow]  Restarting running service {Markup.Escape(step.Service)} " +
                            "so its startup is traced[/]");
                        await RunScAsync($"stop \"{step.Service}\"", 10000);
                        // Wait for STOPPED (sc stop returns at STOP_PENDING) before starting again.
                        for (int i = 0; i < 30; i++)
                        {
                            string q = await RunScAsync($"query \"{step.Service}\"", 5000);
                            if (q.Contains("STOPPED", StringComparison.OrdinalIgnoreCase)) break;
                            await Task.Delay(500);
                        }
                    }

                    if (step.Start)
                        await RunScAsync($"start \"{step.Service}\"", 5000);
                }
                catch { }
            }
        }
        catch { }
    }

    /// <summary>One service the ETW phase acts on: stop it first (restart) and/or start it.</summary>
    internal sealed record ServiceTriggerStep(string Service, bool Stop, bool Start, string? Refusal);

    /// <summary>
    /// What the ETW phase does to each matching auto-start service. Pure: no service is touched.
    /// </summary>
    internal static List<ServiceTriggerStep> PlanServiceTriggers(IEnumerable<string> services, bool targetSet,
        ISet<string> running, Func<string, (bool guarded, string reason)> guard, out bool capExceeded)
    {
        bool restart = ShouldRestartRunningServices(targetSet, running.Count);
        capExceeded = running.Count > 0 && !restart;
        return services
            .Select(s => new ServiceTriggerStep(s, restart && running.Contains(s), true, null))
            .ToList();
    }

    /// <summary>Most running services a --target scan will restart; beyond this it only starts.</summary>
    internal const int MaxServiceRestarts = 5;

    internal static bool ShouldRestartRunningServices(bool targetSet, int runningMatches) =>
        targetSet && runningMatches > 0 && runningMatches <= MaxServiceRestarts;

    internal static bool IsRunningState(string scQueryOutput) =>
        scQueryOutput.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);

    private static async Task<string> RunScAsync(string arguments, int timeoutMs)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return "";
            var stdout = proc.StandardOutput.ReadToEndAsync();
            using var cts = new CancellationTokenSource(timeoutMs);
            try { await proc.WaitForExitAsync(cts.Token); }
            catch { try { proc.Kill(); } catch { } }
            return stdout.IsCompleted ? stdout.Result : "";
        }
        catch { return ""; }
    }

    private async Task TriggerScheduledTasks()
    {
        try
        {
            // When --target is set, only trigger tasks whose binary matches the target.
            var tasks = ScheduledTaskEnumerator.EnumerateScheduledTasks()
                .Where(t => MatchesTarget(t.BinaryPath))
                .GroupBy(t => t.TriggerIdentifier, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();
            foreach (var task in tasks.Take(30))
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/run /tn \"{task.TriggerIdentifier}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    var proc = System.Diagnostics.Process.Start(psi);
                    if (proc != null)
                    {
                        using var cts = new CancellationTokenSource(5000);
                        try { await proc.WaitForExitAsync(cts.Token); }
                        catch { try { proc.Kill(); } catch { } }
                    }
                }
                catch { }
            }
            await Task.Delay(2000);
        }
        catch { }
    }

    private static int GetPriority(DiscoveryContext c) => c.TriggerType switch
    {
        TriggerType.Service when c.IsAutoStart => 10,
        TriggerType.Service => 8,
        TriggerType.ScheduledTask => 6,
        TriggerType.Startup => 5,
        _ => 1
    };
}