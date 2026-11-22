using DLLHijackHunter.Models;

namespace DLLHijackHunter.Safety;

/// <summary>
/// Audit trail of every side effect the tool causes on the machine: files planted, backed up,
/// restored, deleted, delete-failed or delayed; service stop / start / refused-by-guard; task
/// runs; COM activations. Each record goes to the log file at Info level whether or not
/// --verbose is set (with a UTC timestamp and the canary / candidate ID), and to the
/// candidate's CanaryActions list in the JSON report.
/// </summary>
public static class Audit
{
    public static void Record(string actorId, HijackCandidate? candidate, string action, string target,
        string result)
    {
        var utc = DateTime.UtcNow;
        if (candidate != null)
        {
            lock (candidate.CanaryActions)
                candidate.CanaryActions.Add(new CanaryAction { Utc = utc, Action = action, Target = target, Result = result });
        }
        ScanLogger.Audit($"[AUDIT] utc={utc:yyyy-MM-ddTHH:mm:ss.fffZ} id={actorId} " +
            $"candidate={candidate?.Id ?? "-"} action={action} target=\"{target}\" result=\"{result}\"");
    }
}
