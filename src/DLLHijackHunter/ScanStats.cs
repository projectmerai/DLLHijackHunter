namespace DLLHijackHunter;

/// <summary>Per-scan counters printed in the end-of-scan summary (and logged at Info).</summary>
public static class ScanStats
{
    private static int _companionsExamined, _companionsKept, _companionsRejected, _guardSkipped, _duplicatesMerged, _cannotStopSkipped, _selfRecovered;
    public static int CompanionsExamined => _companionsExamined;
    public static int CompanionsKept => _companionsKept;
    public static int CompanionsRejected => _companionsRejected;
    public static int GuardSkipped => _guardSkipped;
    public static int DuplicatesMerged => _duplicatesMerged;
    /// <summary>F6: stopped services not started because the tool could not stop them again.</summary>
    public static int CannotStopSkipped => _cannotStopSkipped;
    /// <summary>F6: services the tool started from Stopped that returned to their snapshot state on their own.</summary>
    public static int SelfRecovered => _selfRecovered;

    internal static void AddCompanions(int examined, int kept, int rejected)
    {
        Interlocked.Add(ref _companionsExamined, examined);
        Interlocked.Add(ref _companionsKept, kept);
        Interlocked.Add(ref _companionsRejected, rejected);
    }
    internal static void AddGuardSkipped(int n) => Interlocked.Add(ref _guardSkipped, n);
    internal static void AddDuplicatesMerged(int n) => Interlocked.Add(ref _duplicatesMerged, n);
    internal static void AddCannotStopSkipped(int n) => Interlocked.Add(ref _cannotStopSkipped, n);
    internal static void AddSelfRecovered(int n) => Interlocked.Add(ref _selfRecovered, n);

    internal static void Reset()
    {
        _companionsExamined = _companionsKept = _companionsRejected = _guardSkipped = _duplicatesMerged = _cannotStopSkipped = _selfRecovered = 0;
    }
}
