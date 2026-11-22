namespace DLLHijackHunter.Safety;

/// <summary>
/// The single place that builds and sends service control commands.
/// </summary>
public static class ServiceControl
{
    /// <summary>Guard decision used for every stop. Replaceable in unit tests.</summary>
    internal static Func<string, (bool guarded, string reason)> Guard { get; set; } = ServiceGuard.IsGuarded;

    /// <summary>sc.exe arguments for a stop, or null when the service must not be stopped.</summary>
    internal static string? BuildStopArguments(string serviceName) => $"stop \"{serviceName}\"";

    internal static string BuildStartArguments(string serviceName) => $"start \"{serviceName}\"";
}
