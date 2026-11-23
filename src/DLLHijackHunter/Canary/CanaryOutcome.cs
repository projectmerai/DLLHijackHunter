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

    /// <summary>
    /// Outcome for a canary that did not fire. main (59bf369): always Timeout.
    /// </summary>
    internal static (CanaryResult result, string? cause, string? note) ClassifyNoFire(HostEvidence evidence) =>
        (CanaryResult.Timeout, null, null);
}
