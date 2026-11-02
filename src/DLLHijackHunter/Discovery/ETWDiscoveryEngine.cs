using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Spectre.Console;
using System.Collections.Concurrent;

namespace DLLHijackHunter.Discovery;

public class ETWDiscoveryEngine
{
    private readonly ScanProfile _profile;
    private readonly ConcurrentDictionary<int, DiscoveryContext> _processes = new();
    private readonly ConcurrentBag<HijackCandidate> _candidates = new();
    private readonly ConcurrentDictionary<string, byte> _failedLookups = new();

    public ETWDiscoveryEngine(ScanProfile profile)
    {
        _profile = profile;
    }

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
            }
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            // ImageFileName in the kernel event is only the short image name ("svchost.exe"),
            // not a path. Resolve the full Win32 path from the live process; fall back to the
            // short name only if the process has already exited.
            string fullPath = TryGetFullImagePath(data.ProcessID) ?? data.ImageFileName ?? "";
            _processes[data.ProcessID] = BuildContext(data.ProcessID, fullPath, data.CommandLine ?? "");
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"ETW ProcessStart handling failed (PID {data.ProcessID}): {ex.Message}");
        }
    }

    private void SeedRunningProcesses()
    {
        try
        {
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                using (p)
                {
                    string? path = TryGetFullImagePath(p.Id);
                    if (path != null)
                        _processes.TryAdd(p.Id, BuildContext(p.Id, path, ""));
                }
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"ETW: could not seed running processes: {ex.Message}");
        }
    }

    private static DiscoveryContext BuildContext(int pid, string binaryPath, string commandLine)
    {
        var ctx = new DiscoveryContext
        {
            Pid = pid,
            BinaryPath = binaryPath,
            CommandLine = commandLine,
            TokenUser = "Unknown",
            IntegrityLevel = "Unknown"
        };

        // Enrich with token info if possible
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            ctx.TokenUser = TokenHelper.GetProcessUser(proc.Handle);
            ctx.IntegrityLevel = TokenHelper.GetProcessIntegrityLevel(proc.Handle);
        }
        catch
        {
            // Protected / exited / access denied — identity stays "Unknown" and is filled
            // from static context data by EnrichWithStaticData where possible.
        }

        return ctx;
    }

    private static string? TryGetFullImagePath(int pid)
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

    private void OnImageLoad(ImageLoadTraceData data)
    {
        try
        {
            string fileName = data.FileName ?? "";
            if (!fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;

            if (_processes.TryGetValue(data.ProcessID, out var ctx))
            {
                // When --target is set, skip processes whose binary is not under the target.
                if (!MatchesTarget(ctx.BinaryPath)) return;

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

                if (AclChecker.IsDirectoryWritableByStandardUser(actualDir))
                {
                    _candidates.Add(new HijackCandidate
                    {
                        BinaryPath = ctx.BinaryPath,
                        DllName = dllName,
                        DllLegitPath = fileName,
                        Type = HijackType.SearchOrder,
                        HijackWritablePath = Path.Combine(actualDir, dllName),
                        RunAsAccount = ctx.TokenUser,
                        DiscoverySource = "etw",
                        Notes = { 
                            $"DLL loaded from writable directory at runtime (PID {data.ProcessID})",
                            "[HEURISTIC] ETW cannot guarantee load priority. Verify search-order precedence manually or via Canary."
                        }
                    });
                }
            }
        }
        catch { }
    }

    private void OnFileIOCreate(FileIOCreateTraceData data)
    {
        try
        {
            string fileName = data.FileName ?? "";
            if (!fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;

            if (!File.Exists(fileName))
            {
                string lookupKey = $"{data.ProcessID}|{fileName}";
                if (_failedLookups.TryAdd(lookupKey, 0))
                {
                    string? dir = Path.GetDirectoryName(fileName);
                    if (dir != null && Directory.Exists(dir) &&
                        AclChecker.IsDirectoryWritableByStandardUser(dir))
                    {
                        string dllName = Path.GetFileName(fileName);
                        string processPath = "";
                        string tokenUser = "Unknown";

                        if (_processes.TryGetValue(data.ProcessID, out var ctx))
                        {
                            // When --target is set, skip processes not under the target.
                            if (!MatchesTarget(ctx.BinaryPath)) return;

                            processPath = ctx.BinaryPath;
                            tokenUser = ctx.TokenUser;
                            ctx.FailedDllLookups.Add(fileName);
                        }

                        _candidates.Add(new HijackCandidate
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
                                $"Phantom DLL detected via ETW (PID {data.ProcessID})",
                                $"Process probed {fileName} but file does not exist",
                                "[HEURISTIC] ETW cannot guarantee load priority. Verify search-order precedence manually or via Canary."
                            }
                        });
                    }
                }
            }
        }
        catch { }
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

            foreach (var svc in services)
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"start \"{svc.TriggerIdentifier}\"",
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
        }
        catch { }
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