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
        var r = await RunScAsync(args, timeoutMs);
        Audit.Record(actorId, candidate, "service-stop", serviceName, Describe(r));
        return r;
    }

    /// <summary>Start a service. Starting is allowed even for guarded services.</summary>
    public static async Task<(ServiceActionOutcome outcome, string output)> StartAsync(string serviceName,
        int timeoutMs, string actorId, HijackCandidate? candidate = null)
    {
        string? args = BuildStartArguments(serviceName);
        if (args == null) return (ServiceActionOutcome.Failed, "invalid service name");
        var r = await RunScAsync(args, timeoutMs);
        Audit.Record(actorId, candidate, "service-start", serviceName, Describe(r));
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

    private static async Task<(ServiceActionOutcome outcome, string output)> RunScAsync(string arguments, int timeoutMs)
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
