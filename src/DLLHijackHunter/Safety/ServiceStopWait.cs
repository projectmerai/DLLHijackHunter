using System.Diagnostics;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;

namespace DLLHijackHunter.Safety;

/// <summary>
/// F3: stop a service and wait for the process it ran in to exit. The SCM reports STOPPED when the service's control
/// handler says so, which can be before its process has exited. The PID is captured before the stop and the wait is
/// audited (process-exit-wait). In the SDK and TIER 5 runs the process had always exited already ("exited 0.0 s"), yet
/// the first delete of a loaded canary still failed: that is handled by the delete's bounded retry
/// (<see cref="ArtifactCleaner.RemoveAsync"/>, f3_cause.md), and the retry/residue path stays as the fallback.
/// </summary>
internal static class ServiceStopWait
{
    internal const int DefaultExitWaitMs = 10_000;
    internal const int PollMs = 250;

    /// <summary>Live process access (replaceable in unit tests).</summary>
    internal static IProcessTable Table { get; set; } = new RealProcessTable();

    public static async Task<(ServiceActionOutcome outcome, string output)> StopAndWaitForExitAsync(string serviceName,
        int timeoutMs, string actorId, HijackCandidate? candidate = null, IProcessTable? table = null,
        int exitWaitMs = DefaultExitWaitMs)
    {
        table ??= Table;
        var before = ServiceControl.Scm.Query(serviceName);
        // The process the service runs in, captured before the stop (its PID is 0 once STOPPED is reported).
        ProcInfo? proc = before.State != SvcState.Stopped && before.Pid > 0 ? table.Current(before.Pid) : null;

        var r = await ServiceControl.StopAsync(serviceName, timeoutMs, actorId, candidate);
        if (r.outcome == ServiceActionOutcome.RefusedByGuard || proc == null) return r;

        string who = $"{(proc.ImagePath.Length > 0 ? Path.GetFileName(proc.ImagePath) : "process")} (PID {proc.Pid})";
        // A shared service host keeps running after one of its services stops: nothing to wait for.
        if (Path.GetFileName(proc.ImagePath).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            Audit.Record(actorId, candidate, "process-exit-wait", who, "not waited: shared service host");
            return r;
        }

        var sw = Stopwatch.StartNew();
        long waited = 0;
        bool alive = table.Find(proc.Pid, proc.StartUtc) != null;
        while (alive && Math.Max(waited, sw.ElapsedMilliseconds) < exitWaitMs)
        {
            await table.Delay(TimeSpan.FromMilliseconds(PollMs));
            waited += PollMs;
            alive = table.Find(proc.Pid, proc.StartUtc) != null;
        }
        double secs = Math.Max(waited, sw.ElapsedMilliseconds) / 1000.0;
        Audit.Record(actorId, candidate, "process-exit-wait", who, alive
            ? FormattableString.Invariant($"still running {secs:0.0} s after the stop (limit {exitWaitMs / 1000} s); delete retries follow")
            : FormattableString.Invariant($"exited {secs:0.0} s after the stop returned"));
        return r;
    }
}
