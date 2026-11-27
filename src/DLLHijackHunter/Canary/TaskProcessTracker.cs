using System.Collections.Concurrent;
using System.Diagnostics;
using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace DLLHijackHunter.Canary;

/// <summary>A process seen starting (or running): PID, parent PID, image path and start time.</summary>
internal sealed record ProcInfo(int Pid, int ParentPid, string ImagePath, DateTime StartUtc);

/// <summary>Live process access used by <see cref="TaskProcessTracker"/> (replaceable in unit tests).</summary>
internal interface IProcessTable
{
    /// <summary>The process with this PID if it is still the same process (same start time), else null.</summary>
    ProcInfo? Find(int pid, DateTime startUtc);
    /// <summary>The process has <paramref name="modulePath"/> loaded or holds it open (Restart Manager).</summary>
    bool HoldsModule(int pid, string modulePath);
    bool Terminate(int pid, out string error);
    Task Delay(TimeSpan t);
    /// <summary>F3: the live process with this PID (image, start time), or null when none.</summary>
    ProcInfo? Current(int pid) => null;
    /// <summary>F3: processes that have <paramref name="path"/> loaded or open (Restart Manager); empty when none.</summary>
    IReadOnlyList<ProcInfo> Holders(string path) => Array.Empty<ProcInfo>();
}

/// <summary>
/// F1: processes a scheduled-task trigger started, and their cleanup when the trigger is stopped.
/// A process is the trigger's only if it started after <c>schtasks /run</c> and its parent chain
/// reaches the Task Scheduler service process; the image name alone never qualifies it.
/// </summary>
internal static class TaskProcessTracker
{
    internal const int PollMs = 500;

    /// <summary>
    /// The processes this task run created: started at or after <paramref name="runUtc"/> (1 s slack for
    /// clock granularity) with a parent chain, through such processes, to a scheduler process.
    /// </summary>
    internal static List<ProcInfo> Collect(IEnumerable<ProcInfo> started, DateTime runUtc, ISet<int> schedulerPids)
    {
        var eligible = started.Where(p => p.StartUtc >= runUtc.AddSeconds(-1) && !schedulerPids.Contains(p.Pid))
            .GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.OrderBy(p => p.StartUtc).Last());
        var result = new List<ProcInfo>();
        foreach (var p in eligible.Values)
        {
            var cur = p;
            for (int depth = 0; depth < 16; depth++)
            {
                if (schedulerPids.Contains(cur.ParentPid)) { result.Add(p); break; }
                // A parent must itself be a process of this run, started before its child.
                if (!eligible.TryGetValue(cur.ParentPid, out var parent) || parent.StartUtc > cur.StartUtc) break;
                cur = parent;
            }
        }
        return result.OrderBy(p => p.StartUtc).ToList();
    }

    /// <summary>
    /// After <c>schtasks /end</c>: wait up to <paramref name="waitMs"/> for the recorded processes to exit.
    /// A recorded process still running and still holding the canary is terminated, unless its image is
    /// guarded or belongs to a security product. Every wait and termination is audited.
    /// </summary>
    internal static async Task CleanupAsync(HijackCandidate candidate, string actorId, IReadOnlyList<ProcInfo> recorded,
        string canaryPath, IProcessTable table, Func<string, bool> isGuardedImage, int waitMs = 10_000)
    {
        if (recorded.Count == 0)
        {
            Audit.Record(actorId, candidate, "task-process-wait", canaryPath, "no processes recorded for this task run");
            return;
        }

        long waited = 0;
        var sw = Stopwatch.StartNew();
        List<ProcInfo> alive;
        while (true)
        {
            alive = recorded.Where(p => table.Find(p.Pid, p.StartUtc) != null).ToList();
            if (alive.Count == 0 || Math.Max(waited, sw.ElapsedMilliseconds) >= waitMs) break;
            await table.Delay(TimeSpan.FromMilliseconds(PollMs));
            waited += PollMs;
        }
        double secs = Math.Max(waited, sw.ElapsedMilliseconds) / 1000.0;

        if (alive.Count == 0)
        {
            Audit.Record(actorId, candidate, "task-process-wait", canaryPath,
                FormattableString.Invariant($"all {recorded.Count} recorded process(es) exited within {secs:0.0} s"));
            return;
        }
        Audit.Record(actorId, candidate, "task-process-wait", canaryPath,
            FormattableString.Invariant($"{alive.Count} of {recorded.Count} recorded process(es) still running after {secs:0.0} s: ") +
            string.Join(", ", alive.Select(p => $"{Path.GetFileName(p.ImagePath)} (PID {p.Pid})")));

        foreach (var rec in alive)
        {
            // The live image (the recorded one can be empty when the process was gone before the trace looked it up).
            var live = table.Find(rec.Pid, rec.StartUtc);
            if (live == null) continue;                                        // exited meanwhile
            string image = !string.IsNullOrEmpty(live.ImagePath) ? live.ImagePath : rec.ImagePath;
            var p = rec with { ImagePath = image };
            string who = $"{(image.Length > 0 ? image : "(image unknown)")} (PID {p.Pid})";
            if (!table.HoldsModule(p.Pid, canaryPath))
            {
                ScanLogger.Debug($"Task process {who} still running but does not hold {canaryPath}; left alone");
                continue;
            }
            if (string.IsNullOrEmpty(p.ImagePath) || !Path.IsPathRooted(p.ImagePath))
            {
                Audit.Record(actorId, candidate, "task-process-terminated", who,
                    "refused: image path unknown, so the guard cannot be checked; left running");
                continue;
            }
            if (isGuardedImage(p.ImagePath))
            {
                Audit.Record(actorId, candidate, "task-process-terminated", who,
                    "refused: guarded or security-product image; left running");
                continue;
            }
            bool ok = table.Terminate(p.Pid, out string err);
            Audit.Record(actorId, candidate, "task-process-terminated", who,
                ok ? $"terminated PID {p.Pid}: started by this task run and still holding the canary"
                   : $"failed to terminate PID {p.Pid}: {err}");
        }
    }
}

/// <summary>Real process table: start-time-checked lookups, Restart Manager / module holder check, Kill.</summary>
internal sealed class RealProcessTable : IProcessTable
{
    public ProcInfo? Find(int pid, DateTime startUtc)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.HasExited) return null;
            var st = p.StartTime.ToUniversalTime();
            if (Math.Abs((st - startUtc).TotalSeconds) > 2) return null;     // PID reused by another process
            return new ProcInfo(pid, 0, ETWDiscoveryEngineAccess.ImagePath(pid) ?? p.ProcessName, st);
        }
        catch { return null; }
    }

    public bool HoldsModule(int pid, string modulePath)
    {
        if (RestartManager.HolderPids(modulePath).Contains(pid)) return true;
        try
        {
            using var p = Process.GetProcessById(pid);
            foreach (ProcessModule m in p.Modules)
                if (string.Equals(m.FileName, modulePath, StringComparison.OrdinalIgnoreCase)) return true;
        }
        catch { }
        return false;
    }

    public bool Terminate(int pid, out string error)
    {
        error = "";
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: false);
            p.WaitForExit(5000);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    public Task Delay(TimeSpan t) => Task.Delay(t);

    public ProcInfo? Current(int pid)
    {
        if (pid <= 0) return null;
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.HasExited) return null;
            return new ProcInfo(pid, 0, ETWDiscoveryEngineAccess.ImagePath(pid) ?? p.ProcessName, p.StartTime.ToUniversalTime());
        }
        catch { return null; }
    }

    public IReadOnlyList<ProcInfo> Holders(string path)
    {
        var list = new List<ProcInfo>();
        foreach (int pid in RestartManager.HolderPids(path))
            list.Add(Current(pid) ?? new ProcInfo(pid, 0, "", DateTime.MinValue));
        return list;
    }
}

internal static class ETWDiscoveryEngineAccess
{
    internal static string? ImagePath(int pid) => Discovery.ETWDiscoveryEngine.TryGetFullImagePath(pid);
}

/// <summary>
/// Records process starts while a task trigger runs: a user-mode ETW session on
/// Microsoft-Windows-Kernel-Process (ProcessStart, with parent PID and create time).
/// </summary>
internal sealed class TaskProcessWatcher : IDisposable
{
    private const string Provider = "Microsoft-Windows-Kernel-Process";
    private const ulong ProcessKeyword = 0x10;   // WINEVENT_KEYWORD_PROCESS
    private readonly TraceEventSession? _session;
    private readonly Task? _pump;
    private readonly ConcurrentBag<ProcInfo> _started = new();
    public string? Error { get; }

    public TaskProcessWatcher()
    {
        try
        {
            _session = new TraceEventSession($"DLLHijackHunter-Task-{Environment.ProcessId}-{Guid.NewGuid():N}") { StopOnDispose = true };
            _session.Source.Dynamic.All += OnEvent;
            _session.EnableProvider(Provider, TraceEventLevel.Informational, ProcessKeyword);
            _pump = Task.Run(() => { try { _session.Source.Process(); } catch { } });
        }
        catch (Exception ex)
        {
            Error = ex.Message;
            try { _session?.Dispose(); } catch { }
            _session = null;
        }
    }

    private void OnEvent(TraceEvent e)
    {
        try
        {
            if (!string.Equals(e.ProviderName, Provider, StringComparison.OrdinalIgnoreCase) || (int)e.ID != 1) return;
            int pid = Convert.ToInt32(e.PayloadByName("ProcessID"));
            int ppid = Convert.ToInt32(e.PayloadByName("ParentProcessID"));
            DateTime start = e.PayloadByName("CreateTime") is DateTime ct ? ct.ToUniversalTime() : e.TimeStamp.ToUniversalTime();
            string image = ETWDiscoveryEngineAccess.ImagePath(pid) ?? (e.PayloadByName("ImageName") as string ?? "");
            _started.Add(new ProcInfo(pid, ppid, image, start));
        }
        catch { }
    }

    /// <summary>Stop recording and return every process start seen.</summary>
    public List<ProcInfo> Stop()
    {
        try { _session?.Stop(); } catch { }
        try { _pump?.Wait(3000); } catch { }
        return _started.ToList();
    }

    public void Dispose() { try { _session?.Dispose(); } catch { } }
}
