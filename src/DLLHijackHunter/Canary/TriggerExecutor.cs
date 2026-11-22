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
                    return await TriggerScheduledTask(candidate.TriggerIdentifier, timeoutSeconds);

                case TriggerType.COM:
                    return await TriggerCOM(candidate.TriggerIdentifier, timeoutSeconds);

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

    // sc.exe could not be started at all (e.g. blocked by antivirus). A timeout is not a launch
    // failure: as in 9c91eab, the confirm-file poll decides the outcome.
    private static bool IsLaunchFailure((ServiceActionOutcome outcome, string output) r) =>
        r.outcome == ServiceActionOutcome.Failed && r.output != "sc.exe timed out";

    private static async Task<bool> TriggerScheduledTask(string taskPath, int timeoutSeconds)
    {
        try
        {
            var (exitCode, _, _) = await RunProcess(
                "schtasks.exe",
                $"/run /tn \"{taskPath}\"",
                timeoutSeconds);

            if (exitCode != 0)
                return false; // schtasks itself failed (task not found, access denied, etc.)

            // Give the task scheduler time to actually launch the process and load the DLL.
            // schtasks /run queues the task and returns quickly; the process launch is async.
            // 8 s covers typical scheduling latency on a moderately loaded system; the canary
            // poll window in CanaryEngine then has the full CanarySettleSeconds remaining.
            await Task.Delay(8000);
            return true; // trigger sent — CanaryEngine's poll decides the outcome
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TriggerCOM(string clsid, int timeoutSeconds)
    {
        try
        {
            // Use PowerShell to instantiate the COM object
            string psCommand = $"[Activator]::CreateInstance(" +
                               $"[Type]::GetTypeFromCLSID('{clsid}'))";

            var (exitCode, _, _) = await RunProcess(
                "powershell.exe",
                $"-NoProfile -Command \"{psCommand}\"",
                timeoutSeconds);

            await Task.Delay(2000);
            return exitCode == 0;
        }
        catch
        {
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