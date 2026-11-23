using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;

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
}

/// <summary>
/// F1: processes a scheduled-task trigger started, and their cleanup when the trigger is stopped.
/// </summary>
internal static class TaskProcessTracker
{
    // TIER 3 (b7541d5) behaviour: no processes are recorded for a task run.
    internal static List<ProcInfo> Collect(IEnumerable<ProcInfo> started, DateTime runUtc, ISet<int> schedulerPids) => new();

    // TIER 3 behaviour: `schtasks /end` only; nothing waited for, nothing terminated.
    internal static Task CleanupAsync(HijackCandidate candidate, string actorId, IReadOnlyList<ProcInfo> recorded,
        string canaryPath, IProcessTable table, Func<string, bool> isGuardedImage, int waitMs = 10_000) =>
        Task.CompletedTask;
}
