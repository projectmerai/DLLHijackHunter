using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using System.Diagnostics;

namespace DLLHijackHunter.Canary;

public static class TriggerExecutor
{
    /// <summary>
    /// Trigger the execution context so it loads the canary DLL.
    /// </summary>
    public static async Task<bool> TriggerAsync(HijackCandidate candidate, int timeoutSeconds = 15,
        string actorId = "canary")
    {
        try
        {
            switch (candidate.Trigger)
            {
                case TriggerType.Service:
                    return await TriggerService(candidate, actorId, timeoutSeconds);

                case TriggerType.ScheduledTask:
                    return await TriggerScheduledTask(candidate, actorId, timeoutSeconds);

                case TriggerType.COM:
                    return await TriggerCOM(candidate, actorId, timeoutSeconds);

                case TriggerType.Startup:
                case TriggerType.RunKey:
                    // Can't easily trigger — would need logoff/logon or reboot
                    return false;

                default:
                    return false;
            }
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TriggerService(HijackCandidate candidate, string actorId, int timeoutSeconds)
    {
        string serviceName = candidate.TriggerIdentifier;
        try
        {
            // Stop the service (may already be stopped by CanaryEngine's pre-deploy stop, but
            // running it again is harmless — ensures any locked file handle is released).
            // ServiceControl refuses guarded services; CanaryEngine never gets here for one.
            var stop = await ServiceControl.StopAsync(serviceName, 10_000, actorId, candidate);
            if (stop.outcome == ServiceActionOutcome.RefusedByGuard || IsLaunchFailure(stop))
                return false;
            await Task.Delay(2000);

            // Start the service. Do NOT gate on sc start exit code: a service that loads the
            // canary DLL and then crashes still fires DllMain (writing the confirm file) before
            // it exits. sc.exe reports that crash as a non-zero exit code, which would make us
            // return false and mark the canary as Failed — even though it actually fired.
            // The poll in CanaryEngine (which checks for the confirm file) is the real oracle.
            var start = await ServiceControl.StartAsync(serviceName, timeoutSeconds * 1000, actorId, candidate);
            if (IsLaunchFailure(start)) return false;
            await Task.Delay(3000); // allow DLL to load and DllMain to execute

            return true; // trigger sent — CanaryEngine's poll decides the outcome
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Stop the candidate's trigger again so a locked canary can be removed: the service
    /// (through ServiceControl, so a guarded one is refused) or the scheduled task's running
    /// instance. Other triggers have nothing to stop.
    /// </summary>
    public static async Task StopTriggerAsync(HijackCandidate candidate, string actorId, string? canaryPath = null)
    {
        switch (candidate.Trigger)
        {
            case TriggerType.Service:
                await ServiceControl.StopAsync(candidate.TriggerIdentifier, 5000, actorId, candidate);
                break;
            case TriggerType.ScheduledTask:
                try
                {
                    var (code, _, err) = await RunProcess("schtasks.exe", $"/end /tn \"{candidate.TriggerIdentifier}\"", 10);
                    Audit.Record(actorId, candidate, "task-end", candidate.TriggerIdentifier,
                        code == 0 ? "sent" : $"failed: exit {code} {err.Trim()}");
                }
                catch (Exception ex)
                {
                    Audit.Record(actorId, candidate, "task-end", candidate.TriggerIdentifier, "failed: " + ex.Message);
                }
                // F1: wait for the processes this task run started; end a survivor that still holds the canary.
                if (canaryPath != null)
                    await TaskProcessTracker.CleanupAsync(candidate, actorId,
                        TaskProcesses.TryGetValue(candidate.Id, out var rec) ? rec : new List<ProcInfo>(),
                        canaryPath, new RealProcessTable(), IsGuardedImage);
                break;
        }
    }

    /// <summary>F1: processes each task-trigger candidate's run created, by candidate id.</summary>
    internal static readonly System.Collections.Concurrent.ConcurrentDictionary<string, List<ProcInfo>> TaskProcesses = new();

    private static void RecordTaskProcesses(HijackCandidate candidate, string actorId, TaskProcessWatcher watcher, DateTime runUtc)
    {
        var started = watcher.Stop();
        if (watcher.Error != null)
        {
            Audit.Record(actorId, candidate, "task-process-recorded", candidate.TriggerIdentifier,
                "not recorded: process-start trace unavailable: " + watcher.Error);
            return;
        }
        var schedulers = new HashSet<int>();
        int sched = ServiceControl.Scm.Query("Schedule").Pid;
        if (sched > 0) schedulers.Add(sched);
        var rec = TaskProcessTracker.Collect(started, runUtc, schedulers);
        TaskProcesses[candidate.Id] = rec;
        Audit.Record(actorId, candidate, "task-process-recorded", candidate.TriggerIdentifier,
            rec.Count == 0 ? $"no process started by the Task Scheduler (PID {sched}) in this run ({started.Count} starts seen)"
                           : string.Join(", ", rec.Select(p => $"{Path.GetFileName(p.ImagePath)} (PID {p.Pid}, parent {p.ParentPid})")));
    }

    private static HashSet<string>? _guardedImages;

    /// <summary>An image under a security-product folder, or the binary of a guarded service: never terminated.</summary>
    internal static bool IsGuardedImage(string imagePath)
    {
        if (ServiceGuard.IsSecurityProductImage(imagePath)) return true;
        _guardedImages ??= Discovery.ServiceEnumerator.EnumerateServices()
            .Where(s => ServiceControl.Guard(s.TriggerIdentifier).guarded)
            .Select(s => s.BinaryPath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return _guardedImages.Contains(imagePath);
    }

    // sc.exe could not be started at all (e.g. blocked by antivirus). A timeout is not a launch
    // failure: as in 9c91eab, the confirm-file poll decides the outcome.
    private static bool IsLaunchFailure((ServiceActionOutcome outcome, string output) r) =>
        r.outcome == ServiceActionOutcome.Failed && r.output != "sc.exe timed out";

    private static async Task<bool> TriggerScheduledTask(HijackCandidate candidate, string actorId, int timeoutSeconds)
    {
        string taskPath = candidate.TriggerIdentifier;
        // F1: record the processes this run creates (parent chain to the Task Scheduler service,
        // started after /run), so a survivor holding the canary can be ended at cleanup.
        using var watcher = new TaskProcessWatcher();
        DateTime runUtc = DateTime.UtcNow;
        try
        {
            var (exitCode, _, stderr) = await RunProcess(
                "schtasks.exe",
                $"/run /tn \"{taskPath}\"",
                timeoutSeconds);
            Audit.Record(actorId, candidate, "task-run", taskPath,
                exitCode == 0 ? "sent" : $"failed: exit {exitCode} {stderr.Trim()}");

            if (exitCode != 0)
                return false; // schtasks itself failed (task not found, access denied, etc.)

            // Give the task scheduler time to actually launch the process and load the DLL.
            // schtasks /run queues the task and returns quickly; the process launch is async.
            // 8 s covers typical scheduling latency on a moderately loaded system; the canary
            // poll window in CanaryEngine then has the full CanarySettleSeconds remaining.
            await Task.Delay(8000);
            RecordTaskProcesses(candidate, actorId, watcher, runUtc);
            return true; // trigger sent — CanaryEngine's poll decides the outcome
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TriggerCOM(HijackCandidate candidate, string actorId, int timeoutSeconds)
    {
        string clsid = candidate.TriggerIdentifier;
        try
        {
            // Use PowerShell to instantiate the COM object
            string psCommand = $"[Activator]::CreateInstance(" +
                               $"[Type]::GetTypeFromCLSID('{clsid}'))";

            var (exitCode, _, _) = await RunProcess(
                "powershell.exe",
                $"-NoProfile -Command \"{psCommand}\"",
                timeoutSeconds);
            Audit.Record(actorId, candidate, "com-activation", clsid,
                exitCode == 0 ? "activated" : $"failed: exit {exitCode}");

            await Task.Delay(2000);
            return exitCode == 0;
        }
        catch (Exception ex)
        {
            Audit.Record(actorId, candidate, "com-activation", clsid, "failed: " + ex.Message);
            return false;
        }
    }

    private static async Task<(int exitCode, string stdout, string stderr)> RunProcess(
        string fileName,
        string arguments,
        int timeoutSeconds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        if (proc == null)
            return (-1, string.Empty, string.Empty);

        Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = proc.StandardError.ReadToEndAsync();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));

        try
        {
            await proc.WaitForExitAsync(cts.Token);
            string stdout = await stdoutTask;
            string stderr = await stderrTask;
            return (proc.ExitCode, stdout, stderr);
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            string stdout = string.Empty;
            string stderr = string.Empty;

            try { stdout = await stdoutTask; } catch { }
            try { stderr = await stderrTask; } catch { }

            return (-1, stdout, stderr);
        }
    }
}