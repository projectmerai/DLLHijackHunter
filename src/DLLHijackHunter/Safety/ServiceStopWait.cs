using System.Diagnostics;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;

namespace DLLHijackHunter.Safety;

/// <summary>
/// F3: stop a service and wait for the process it ran in to exit, and for the planted file to be released. The SCM
/// reports STOPPED when the service's control handler says so, before its process has exited and unmapped its DLLs: in
/// the SDK run every canary cleanup's first delete failed with "Access denied" ~1 ms after "state Stopped", and
/// succeeded on the retry; a second failure would have been residue and exit code 4. The service's own process was not
/// always the last holder (TIER 5 VM run: it had exited, the delete still failed 1 ms later), so after the PID has exited
/// the wait continues, within the same budget, until no process holds <c>heldFile</c> (Restart Manager), naming the
/// holders. The PID is captured before the stop; the wait is audited (process-exit-wait). The delete's retry and residue
/// path stays as the fallback.
/// </summary>
internal static class ServiceStopWait
{
    internal const int DefaultExitWaitMs = 10_000;
    internal const int PollMs = 250;

    /// <summary>Live process access (replaceable in unit tests).</summary>
    internal static IProcessTable Table { get; set; } = new RealProcessTable();

    public static async Task<(ServiceActionOutcome outcome, string output)> StopAndWaitForExitAsync(string serviceName,
        int timeoutMs, string actorId, HijackCandidate? candidate = null, IProcessTable? table = null,
        int exitWaitMs = DefaultExitWaitMs, string? heldFile = null)
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
        long Elapsed() => Math.Max(waited, sw.ElapsedMilliseconds);
        async Task Tick() { await table.Delay(TimeSpan.FromMilliseconds(PollMs)); waited += PollMs; }

        bool alive = table.Find(proc.Pid, proc.StartUtc) != null;
        while (alive && Elapsed() < exitWaitMs) { await Tick(); alive = table.Find(proc.Pid, proc.StartUtc) != null; }
        double exitSecs = Elapsed() / 1000.0;
        string result = alive
            ? FormattableString.Invariant($"still running {exitSecs:0.0} s after the stop (limit {exitWaitMs / 1000} s); delete retries follow")
            : FormattableString.Invariant($"exited {exitSecs:0.0} s after the stop returned");

        // Then the planted file itself: another process (e.g. a child the service started) may still have it mapped.
        if (!alive && heldFile != null)
        {
            var seen = new Dictionary<int, string>();
            var holders = table.Holders(heldFile);
            while (holders.Count > 0 && Elapsed() < exitWaitMs)
            {
                foreach (var h in holders) seen.TryAdd(h.Pid, $"{(h.ImagePath.Length > 0 ? Path.GetFileName(h.ImagePath) : "process")} (PID {h.Pid})");
                await Tick();
                holders = table.Holders(heldFile);
            }
            double heldSecs = Elapsed() / 1000.0;
            if (holders.Count > 0)
            {
                foreach (var h in holders) seen.TryAdd(h.Pid, $"{(h.ImagePath.Length > 0 ? Path.GetFileName(h.ImagePath) : "process")} (PID {h.Pid})");
                result += FormattableString.Invariant($"; {Path.GetFileName(heldFile)} still held after {heldSecs:0.0} s by ") +
                    string.Join(", ", holders.Select(h => seen[h.Pid])) + "; delete retries follow";
            }
            else if (seen.Count > 0)
                result += FormattableString.Invariant($"; {Path.GetFileName(heldFile)} released by ") + string.Join(", ", seen.Values) +
                    FormattableString.Invariant($" {heldSecs:0.0} s after the stop");
            else
                result += $"; {Path.GetFileName(heldFile)} not held";
        }
        Audit.Record(actorId, candidate, "process-exit-wait", who, result);
        return r;
    }
}
