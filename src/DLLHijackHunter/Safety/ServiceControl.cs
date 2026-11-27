using System.Diagnostics;
using DLLHijackHunter.Models;

namespace DLLHijackHunter.Safety;

public enum ServiceActionOutcome
{
    Sent,            // sc.exe ran (its own exit code is in Output; callers poll state themselves)
    RefusedByGuard,  // the guard refused; no process was started
    Failed           // sc.exe could not be started or timed out (e.g. blocked by antivirus)
}

/// <summary>
/// The single place that builds and sends service control commands. Every stop, start and
/// restart the tool performs goes through here, and a stop for a guarded service cannot be
/// built: <see cref="BuildStopArguments"/> returns null for it.
/// </summary>
public static class ServiceControl
{
    /// <summary>SCM access (status queries and commands). Replaceable in unit tests.</summary>
    internal static IScm Scm { get; set; } = new RealScm();

    /// <summary>Per-scan service snapshot and touched-service record.</summary>
    internal static ServiceStateTracker Tracker { get; set; } = new();

    /// <summary>How long a stop or start waits for the SCM to reach the requested state. A busy
    /// service (Checkmk's ~30 s start-up migration step) can hold a stop control that long.</summary>
    internal static int StateWaitMs { get; set; } = 60_000;
    internal static int PollMs { get; set; } = 250;
    /// <summary>Backoff between restore attempts (~3 attempts over ~30 s, waits included).</summary>
    internal static int[] RestoreBackoffMs { get; set; } = { 0, 5_000, 10_000 };

    /// <summary>
    /// Poll the real SCM status until it leaves START/STOP/CONTINUE/PAUSE_PENDING (or the
    /// timeout passes). Returns the last status read.
    /// </summary>
    public static Task<SvcStatus> WaitForStableAsync(string serviceName, int timeoutMs) =>
        WaitUntilAsync(serviceName, timeoutMs, s => !s.IsPending);

    private static async Task<SvcStatus> WaitUntilAsync(string serviceName, int timeoutMs, Func<SvcStatus, bool> done)
    {
        // Elapsed time is the sum of the waits (so a fake SCM with instant delays stays
        // deterministic) or the wall clock, whichever is larger.
        var sw = Stopwatch.StartNew();
        long waited = 0;
        var s = Scm.Query(serviceName);
        while (!done(s) && Math.Max(waited, sw.ElapsedMilliseconds) < timeoutMs)
        {
            await Scm.Delay(TimeSpan.FromMilliseconds(PollMs));
            waited += PollMs;
            s = Scm.Query(serviceName);
        }
        return s;
    }

    /// <summary>
    /// Record the service's state, start type and PID in the scan's snapshot, once. A later call
    /// returns the first snapshot and never overwrites it. A service caught mid-transition is
    /// snapshotted at the stable state it settles in.
    /// </summary>
    public static async Task<SvcStatus> EnsureSnapshotAsync(string serviceName)
    {
        if (Tracker.Snapshot(serviceName) is SvcStatus existing) return existing;
        var s = Scm.Query(serviceName);
        if (s.IsPending) s = await WaitForStableAsync(serviceName, StateWaitMs);
        Tracker.Record(serviceName, s);
        return Tracker.Snapshot(serviceName)!;
    }

    /// <summary>Whether the service was RUNNING in the scan's snapshot (never a live query).
    /// A service with no snapshot yet is snapshotted now.</summary>
    public static bool WasRunningAtSnapshot(string serviceName)
    {
        var s = Tracker.Snapshot(serviceName) ?? EnsureSnapshotAsync(serviceName).GetAwaiter().GetResult();
        return s.State == SvcState.Running;
    }

    /// <summary>
    /// Compare the service with its snapshot; if it differs, start or stop it, wait for a stable
    /// state and verify, retrying with backoff. Returns null when the service matches its
    /// snapshot (or has none), otherwise a <c>service-state</c> residue entry. One audit line
    /// per restore attempt.
    /// </summary>
    public static async Task<ResidueEntry?> RestoreAsync(string serviceName, string actorId, HijackCandidate? candidate = null)
    {
        var snap = Tracker.Snapshot(serviceName);
        if (snap == null || snap.State is not (SvcState.Running or SvcState.Stopped)) return null;

        var cur = await WaitForStableAsync(serviceName, StateWaitMs);
        if (cur.State == snap.State) return null;

        string lastError = "";
        for (int attempt = 0; attempt < RestoreBackoffMs.Length; attempt++)
        {
            if (RestoreBackoffMs[attempt] > 0) await Scm.Delay(TimeSpan.FromMilliseconds(RestoreBackoffMs[attempt]));
            cur = await WaitForStableAsync(serviceName, StateWaitMs);
            if (cur.State == snap.State)
            {
                Audit.Record(actorId, candidate, "service-restore", serviceName,
                    $"attempt {attempt + 1}: already {cur.State} (snapshot {snap.State})");
                return null;
            }

            (ServiceActionOutcome outcome, string output) r = snap.State == SvcState.Running
                ? await StartAsync(serviceName, 20_000, actorId, candidate)
                : await StopAsync(serviceName, 20_000, actorId, candidate);
            cur = Scm.Query(serviceName);
            bool ok = cur.State == snap.State;
            if (!ok) lastError = r.outcome == ServiceActionOutcome.Sent ? FirstLine(r.output) : $"{r.outcome}: {FirstLine(r.output)}";
            Audit.Record(actorId, candidate, "service-restore", serviceName,
                $"attempt {attempt + 1}: expected {snap.State}, now {cur.State}" + (ok ? " (restored)" : $" ({lastError})"));
            if (ok) return null;
        }

        return new ResidueEntry
        {
            Kind = "service-state",
            Service = serviceName,
            Path = "service:" + serviceName,
            ExpectedState = snap.State.ToString(),
            ActualState = cur.State.ToString(),
            LastError = string.IsNullOrEmpty(lastError) ? "state did not change" : lastError,
            CandidateId = candidate?.Id,
            Reason = $"service {serviceName} could not be restored to {snap.State} (now {cur.State})"
        };
    }

    /// <summary>Restore every service the tool sent a stop or start to (end of the canary and ETW phases).</summary>
    public static async Task<List<ResidueEntry>> RestoreAllAsync(string actorId)
    {
        var residue = new List<ResidueEntry>();
        foreach (var name in Tracker.Touched)
            if (await RestoreAsync(name, actorId) is ResidueEntry r) residue.Add(r);
        return residue;
    }

    private static string FirstLine(string s)
    {
        var t = (s ?? "").Trim();
        var lines = t.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        // sc.exe prints "[SC] ControlService FAILED 1061:" then the message on the next line.
        var failed = lines.FirstOrDefault(l => l.Contains("FAILED", StringComparison.OrdinalIgnoreCase));
        return failed ?? (lines.Length > 0 ? lines[0] : "");
    }

    /// <summary>sc.exe reported that the command was not accepted (FAILED nnnn).</summary>
    private static bool Rejected((ServiceActionOutcome outcome, string output) r) =>
        r.outcome == ServiceActionOutcome.Sent && r.output.Contains("FAILED", StringComparison.OrdinalIgnoreCase);

    private static string WithState((ServiceActionOutcome outcome, string output) r, SvcStatus s) =>
        Describe(r) + $"; state {s.State}" + (s.Pid > 0 ? $" pid {s.Pid}" : "");

    /// <summary>Guard decision used for every stop. Replaceable in unit tests.</summary>
    internal static Func<string, (bool guarded, string reason)> Guard { get; set; } = ServiceGuard.IsGuarded;

    /// <summary>sc.exe arguments for a stop, or null when the service must not be stopped.</summary>
    internal static string? BuildStopArguments(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || serviceName.Contains('"')) return null;
        return Guard(serviceName).guarded ? null : $"stop \"{serviceName}\"";
    }

    internal static string? BuildStartArguments(string serviceName) =>
        string.IsNullOrWhiteSpace(serviceName) || serviceName.Contains('"') ? null : $"start \"{serviceName}\"";

    /// <summary>Stop a service unless the guard refuses it. Audited either way.</summary>
    public static async Task<(ServiceActionOutcome outcome, string output)> StopAsync(string serviceName,
        int timeoutMs, string actorId, HijackCandidate? candidate = null)
    {
        string? args = BuildStopArguments(serviceName);
        if (args == null)
        {
            string why = Guard(serviceName).reason;
            Audit.Record(actorId, candidate, "service-stop", serviceName,
                "refused-by-guard" + (why.Length > 0 ? $": {why}" : ""));
            return (ServiceActionOutcome.RefusedByGuard, why);
        }
        await EnsureSnapshotAsync(serviceName);
        // A control sent while the service is mid-transition is rejected (1061): settle first.
        var settled = await WaitForStableAsync(serviceName, StateWaitMs);
        // F3: a service that is already Stopped gets no second stop (the SDK timelines showed a stop after the
        // pre-deploy stop, and another after a failed delete; sc.exe only answers 1062 "not started").
        if (settled.State is SvcState.Stopped or SvcState.NotFound)
        {
            ScanLogger.Debug($"service-stop {serviceName}: not sent, already {settled.State}");
            return (ServiceActionOutcome.Sent, $"not sent: already {settled.State}");
        }
        Tracker.MarkStop(serviceName);
        var r = await Scm.SendAsync("stop", serviceName, timeoutMs);
        // A stop that sc.exe gave up on is still queued at the SCM and lands later: wait for
        // STOPPED unless sc.exe reported it was rejected outright.
        var s = Rejected(r)
            ? await WaitForStableAsync(serviceName, StateWaitMs)
            : await WaitUntilAsync(serviceName, StateWaitMs, x => x.State is SvcState.Stopped or SvcState.NotFound);
        if (s.IsPending) s = await WaitForStableAsync(serviceName, StateWaitMs);
        Audit.Record(actorId, candidate, "service-stop", serviceName, WithState(r, s));
        return r;
    }

    /// <summary>Start a service. Starting is allowed even for guarded services.</summary>
    public static async Task<(ServiceActionOutcome outcome, string output)> StartAsync(string serviceName,
        int timeoutMs, string actorId, HijackCandidate? candidate = null)
    {
        string? args = BuildStartArguments(serviceName);
        if (args == null) return (ServiceActionOutcome.Failed, "invalid service name");
        await EnsureSnapshotAsync(serviceName);
        await WaitForStableAsync(serviceName, StateWaitMs);
        Tracker.MarkStart(serviceName);
        var r = await Scm.SendAsync("start", serviceName, timeoutMs);
        // The SCM marks the service START_PENDING before StartService returns (or sc.exe gives
        // up), so waiting for a stable state covers both a normal and a slow start.
        var s = await WaitForStableAsync(serviceName, StateWaitMs);
        Audit.Record(actorId, candidate, "service-start", serviceName, WithState(r, s));
        return r;
    }

    /// <summary>Read-only state query (not audited: it changes nothing).</summary>
    public static async Task<string> QueryAsync(string serviceName, int timeoutMs)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || serviceName.Contains('"')) return "";
        return (await RunScAsync($"query \"{serviceName}\"", timeoutMs)).output;
    }

    private static string Describe((ServiceActionOutcome outcome, string output) r) =>
        r.outcome == ServiceActionOutcome.Sent ? "sent" : $"failed: {r.output}";

    internal static async Task<(ServiceActionOutcome outcome, string output)> RunScAsync(string arguments, int timeoutMs)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return (ServiceActionOutcome.Failed, "sc.exe did not start");
            var stdout = proc.StandardOutput.ReadToEndAsync();
            using var cts = new CancellationTokenSource(timeoutMs);
            try { await proc.WaitForExitAsync(cts.Token); }
            catch
            {
                try { proc.Kill(); } catch { }
                return (ServiceActionOutcome.Failed, "sc.exe timed out");
            }
            return (ServiceActionOutcome.Sent, stdout.IsCompleted ? stdout.Result : "");
        }
        catch (Exception ex)
        {
            return (ServiceActionOutcome.Failed, ex.Message);
        }
    }
}
