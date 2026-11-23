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

/// <summary>How long a canary waits for its confirm file, and how its firing time is recorded.</summary>
internal static class CanaryWait
{
    /// <summary>Milliseconds to wait for the confirm file once the trigger has been sent.
    /// main (59bf369): the profile's settle window for every trigger.</summary>
    internal static int ForTrigger(TriggerType trigger, int settleSeconds, int serviceWaitSeconds) =>
        settleSeconds * 1000;

    /// <summary>Audit text for a fired canary: seconds from the reference time to the confirm file.
    /// main: no timing recorded.</summary>
    internal static string FiredText(DateTime referenceUtc, DateTime confirmUtc, string reference) => "";
}
