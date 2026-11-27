namespace DLLHijackHunter.Canary;

/// <summary>
/// F4: when a canary fired, relative to the plant and to the trigger request (a service start request), and whether
/// that was before the service reported RUNNING. A load during process start-up (the SDK run's CLR start-up loads
/// cryptsp.dll before the ServiceBase handshake) fires before RUNNING; the old text printed that as a negative
/// "-0.4 s after service RUNNING", which reads like a clock error. A negative "after" value is never printed.
/// </summary>
internal static class FireTime
{
    /// <summary>
    /// "confirm file written 2.2 s after plant, 0.2 s after start request (before RUNNING)". <paramref name="requestUtc"/>
    /// is when the trigger was requested (<paramref name="requestLabel"/>: "start request", "trigger");
    /// <paramref name="runningUtc"/> is when the service was seen RUNNING (null for other triggers).
    /// </summary>
    internal static string Describe(DateTime plantedUtc, DateTime? requestUtc, string requestLabel, DateTime? runningUtc,
        DateTime confirmUtc)
    {
        var s = new System.Text.StringBuilder("confirm file written ");
        s.Append(After(plantedUtc, confirmUtc, "plant"));
        if (requestUtc is DateTime req) s.Append(", ").Append(After(req, confirmUtc, requestLabel));
        if (runningUtc is DateTime run)
            s.Append(confirmUtc < run ? " (before RUNNING)" : ", " + After(run, confirmUtc, "RUNNING"));
        return s.ToString();
    }

    /// <summary>The exact times and signed differences, for CanaryActions (never printed on the console).</summary>
    internal static string Exact(DateTime plantedUtc, DateTime? requestUtc, DateTime? runningUtc, DateTime confirmUtc)
    {
        string T(DateTime t) => t.ToString("HH:mm:ss.fff") + "Z";
        string D(DateTime a, DateTime b) => FormattableString.Invariant($"{(b - a).TotalSeconds:+0.000;-0.000;0.000}");
        var parts = new List<string> { $"plant {T(plantedUtc)}" };
        if (requestUtc is DateTime req) parts.Add($"request {T(req)}");
        if (runningUtc is DateTime run) parts.Add($"RUNNING seen {T(run)}");
        parts.Add($"confirm {T(confirmUtc)}");
        var diffs = new List<string> { $"confirm-plant {D(plantedUtc, confirmUtc)} s" };
        if (requestUtc is DateTime r2) diffs.Add($"confirm-request {D(r2, confirmUtc)} s");
        if (runningUtc is DateTime r3) diffs.Add($"confirm-RUNNING {D(r3, confirmUtc)} s");
        return $"[exact: {string.Join(", ", parts)}; {string.Join(", ", diffs)}]";
    }

    /// <summary>"x.x s after <label>", or "before <label>" when the confirm file came first.</summary>
    private static string After(DateTime reference, DateTime confirmUtc, string label) =>
        confirmUtc < reference
            ? $"before {label}"
            : FormattableString.Invariant($"{(confirmUtc - reference).TotalSeconds:0.0} s after {label}");
}
