using System.Diagnostics.Eventing.Reader;
using DLLHijackHunter.Models;

namespace DLLHijackHunter.Canary;

/// <summary>What the host did after a canary was planted and the trigger was sent.</summary>
internal sealed record HostEvidence(
    DateTime PlantedUtc,
    string PlantedPath,
    // Windows event-log records seen after the plant: (provider, event id, message).
    IReadOnlyList<(string Provider, int Id, string Message)> Events);

internal static class CanaryOutcome
{
    internal const string HostFailedAfterPlant = "host-failed-after-plant";

    // Application Error 1000 (crash), Windows Error Reporting 1001 (crash/hang report) and
    // Application Popup 26 (loader errors such as "Entry Point Not Found", 0xC000007B).
    private static readonly (string Provider, int Id)[] CrashEvents =
    {
        ("Application Error", 1000), ("Windows Error Reporting", 1001), ("Application Popup", 26),
    };

    /// <summary>The planted file and the proxy's sidecar next to it (both are "the planted module").</summary>
    private static IEnumerable<string> PlantedModules(string plantedPath)
    {
        yield return plantedPath;
        string? dir = Path.GetDirectoryName(plantedPath);
        if (dir != null)
            yield return Path.Combine(dir, Path.GetFileNameWithoutExtension(plantedPath) + "_hhorig.dll");
    }

    /// <summary>
    /// Outcome for a canary that did not fire. A crash or loader failure after the plant whose
    /// evidence names the planted module (its full path) is Failed(host-failed-after-plant), which
    /// carries no penalty and is not Confirmed. Anything else is Timeout.
    /// </summary>
    internal static (CanaryResult result, string? cause, string? note) ClassifyNoFire(HostEvidence evidence)
    {
        var modules = PlantedModules(evidence.PlantedPath).ToList();
        foreach (var (provider, id, message) in evidence.Events)
        {
            if (!CrashEvents.Any(e => e.Id == id && string.Equals(e.Provider, provider, StringComparison.OrdinalIgnoreCase)))
                continue;
            if (string.IsNullOrEmpty(message)) continue;
            string? named = modules.FirstOrDefault(m => message.Contains(m, StringComparison.OrdinalIgnoreCase));
            if (named == null) continue;
            return (CanaryResult.Failed, HostFailedAfterPlant,
                $"Host failed after the canary was planted ({provider} {id} names {named}): the loader reached " +
                "the planted file, but the canary could not confirm. Inconclusive; no confidence penalty.");
        }
        return (CanaryResult.Timeout, null, null);
    }

    /// <summary>
    /// Application and System event-log records from the crash providers since
    /// <paramref name="sinceUtc"/> (read-only). Errors reading a log are ignored.
    /// </summary>
    internal static List<(string Provider, int Id, string Message)> ReadEventsSince(DateTime sinceUtc)
    {
        var list = new List<(string, int, string)>();
        string since = sinceUtc.AddSeconds(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        foreach (var (log, providers) in new[]
                 {
                     ("Application", new[] { "Application Error", "Windows Error Reporting" }),
                     ("System", new[] { "Application Popup" }),
                 })
        {
            try
            {
                string prov = string.Join(" or ", providers.Select(p => $"@Name='{p}'"));
                string xpath = $"*[System[Provider[{prov}] and TimeCreated[@SystemTime>='{since}']]]";
                using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath));
                for (int n = 0; n < 200 && reader.ReadEvent() is EventRecord rec; n++)
                {
                    using (rec)
                    {
                        string msg;
                        try { msg = rec.FormatDescription() ?? ""; } catch { msg = ""; }
                        if (msg.Length == 0)
                            msg = string.Join(" ", rec.Properties.Select(p => p.Value?.ToString() ?? ""));
                        list.Add((rec.ProviderName, rec.Id, msg));
                    }
                }
            }
            catch (Exception ex)
            {
                ScanLogger.Debug($"Event log {log} could not be read: {ex.Message}");
            }
        }
        return list;
    }
}

/// <summary>How long a canary waits for its confirm file, and how its firing time is recorded.</summary>
internal static class CanaryWait
{
    /// <summary>
    /// Milliseconds to wait for the confirm file once the trigger has been sent. A Service trigger
    /// returns once the service is stably RUNNING (R3); the service may still launch the process
    /// that loads the DLL much later (Checkmk starts cmk-agent-ctl.exe ~31 s after every start),
    /// so it waits up to the service wait (default 90 s), never less than the settle window.
    /// Other triggers keep the settle window.
    /// </summary>
    internal static int ForTrigger(TriggerType trigger, int settleSeconds, int serviceWaitSeconds) =>
        trigger == TriggerType.Service
            ? Math.Max(settleSeconds, serviceWaitSeconds) * 1000
            : settleSeconds * 1000;

    /// <summary>Audit text for a fired canary: seconds from the reference time to the confirm file.</summary>
    internal static string FiredText(DateTime referenceUtc, DateTime confirmUtc, string reference) =>
        FormattableString.Invariant($"confirm file written {(confirmUtc - referenceUtc).TotalSeconds:0.0} s after {reference}");
}
