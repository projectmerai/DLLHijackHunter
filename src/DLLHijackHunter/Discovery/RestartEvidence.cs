using DLLHijackHunter.Models;

namespace DLLHijackHunter.Discovery;

/// <summary>
/// Evidence that makes a running service worth restarting under --restart-services, and the
/// ETW observation that lifts a companion finding's Medium cap.
/// </summary>
internal static class RestartEvidence
{
    /// <summary>
    /// Evidence for a service: a companion executable in a user-writable directory (R4 C), or a
    /// service binary directory a standard user can write to. Null: no evidence, never restarted.
    /// </summary>
    internal static Func<string, string?> For(IEnumerable<DiscoveryContext> contexts,
        IEnumerable<CompanionDiscovery.Companion> companions,
        Func<string, string?, bool>? isDirWritable = null)
    {
        isDirWritable ??= (d, a) => Native.AclChecker.IsDirectoryWritableByStandardUser(d, a);
        var byService = companions.GroupBy(c => c.Service, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().ExePath, StringComparer.OrdinalIgnoreCase);
        var binaries = contexts.Where(c => c.TriggerType == TriggerType.Service && !c.IsCompanion && !c.IsSvchostService)
            .GroupBy(c => c.TriggerIdentifier, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        return name =>
        {
            if (byService.TryGetValue(name, out var exe))
                return $"companion finding: {exe} is in a directory a standard user can write to";
            if (binaries.TryGetValue(name, out var ctx) && Path.GetDirectoryName(ctx.BinaryPath) is string dir)
            {
                try
                {
                    if (isDirWritable(dir, ctx.RunAsAccount))
                        return $"writable binary directory: {dir}";
                }
                catch { }
            }
            return null;
        };
    }

    /// <summary>
    /// A companion finding whose executable ETW saw run with its service's binary as parent is
    /// observed: the Medium cap no longer applies.
    /// </summary>
    internal static void MarkObservedCompanions(List<HijackCandidate> candidates,
        IEnumerable<(string Binary, string Parent)> observed, IEnumerable<DiscoveryContext> contexts)
    {
        var serviceBinaries = contexts.Where(c => c.TriggerType == TriggerType.Service && !c.IsCompanion)
            .GroupBy(c => c.TriggerIdentifier, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(c => c.BinaryPath).ToHashSet(StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase);
        var seen = observed.ToList();
        foreach (var c in candidates.Where(c => c.CompanionOf != null && !c.CompanionObserved))
        {
            if (!serviceBinaries.TryGetValue(c.CompanionOf!, out var parents)) continue;
            if (!seen.Any(p => p.Binary.Equals(c.BinaryPath, StringComparison.OrdinalIgnoreCase) && parents.Contains(p.Parent)))
                continue;
            c.CompanionObserved = true;
            c.Notes.Remove(CompanionDiscovery.Note(c.CompanionOf!));
            c.Notes.Add($"observed running as a child of {c.CompanionOf} during the ETW phase");
        }
    }
}
