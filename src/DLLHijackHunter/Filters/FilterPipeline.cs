using DLLHijackHunter.Models;
using Spectre.Console;

namespace DLLHijackHunter.Filters;

public class FilterPipeline
{
    private readonly List<IHardGate> _hardGates;
    private readonly List<ISoftGate> _softGates;
    private readonly ScanProfile _profile;

    public FilterPipeline(ScanProfile profile)
    {
        _profile = profile;

        _hardGates = new List<IHardGate>
        {
            new ApiSetSchemaFilter(),
            new KnownDllsFilter(),
            new WritabilityFilter(_profile.LpeOnly)
        };

        _softGates = new List<ISoftGate>
        {
            new WinSxSManifestFilter(),
            new PrivilegeDeltaFilter(),
            new LoadLibraryExFlagsFilter(),
            new SignatureVerificationFilter(),
            new ErrorHandledLoadFilter()
        };
    }

    public List<HijackCandidate> Process(List<HijackCandidate> candidates)
    {
        var remaining = candidates;
        int initialCount = remaining.Count;

        AnsiConsole.MarkupLine("\n[bold cyan]═══ Filter Pipeline ═══[/]");

        // ═══ HARD GATES (binary kill) ═══
        AnsiConsole.MarkupLine("[bold]Hard Gates (binary kill):[/]");

        foreach (var gate in _hardGates)
        {
            int before = remaining.Count;
            remaining = gate.Apply(remaining);
            int removed = before - remaining.Count;
            double pct = before > 0 ? (removed * 100.0 / before) : 0;

            string color = removed > 0 ? "red" : "green";
            AnsiConsole.MarkupLine($"  [{color}]  {gate.Name}: {before} → {remaining.Count} " +
                $"(removed {removed}, {pct:F0}%)[/]");
            ScanLogger.Debug($"Hard gate '{gate.Name}': {before} → {remaining.Count} (removed {removed}, {pct:F0}%)");
        }

        int afterHardGates = remaining.Count;
        AnsiConsole.MarkupLine($"[bold]  Survived hard gates: {afterHardGates}[/]");

        // ═══ SOFT GATES (confidence adjustment) ═══
        AnsiConsole.MarkupLine("\n[bold]Soft Gates (confidence adjustment):[/]");

        var softGatePenaltyCounts = new Dictionary<string, int>();
        foreach (var gate in _softGates)
            softGatePenaltyCounts[gate.Name] = 0;

        foreach (var candidate in remaining)
        {
            candidate.Confidence = 100.0;

            foreach (var gate in _softGates)
            {
                try
                {
                    var (penalty, reason) = gate.Evaluate(candidate);

                    if (penalty > 0)
                    {
                        candidate.Confidence -= penalty;
                        softGatePenaltyCounts[gate.Name]++;

                        if (reason != null)
                            candidate.Notes.Add($"[{gate.Name}] -{penalty:F0}%: {reason}");
                    }
                }
                catch
                {
                    // Soft gate evaluation failed — don't penalize
                }
            }

            candidate.Confidence = Math.Clamp(candidate.Confidence, 0, 100);
        }

        foreach (var gate in _softGates)
        {
            int affected = softGatePenaltyCounts[gate.Name];
            AnsiConsole.MarkupLine($"  [yellow]  {gate.Name}: penalized {affected} candidates[/]");
        }

        // ═══ DEDUPLICATE ═══
        remaining = Deduplicate(remaining);
        AnsiConsole.MarkupLine($"\n[bold]After deduplication: {remaining.Count}[/]");

        // ═══ FILTER BY PROFILE ═══
        if (!_profile.IncludeSamePrivilege)
        {
            int beforePrivFilter = remaining.Count;
            remaining = remaining.Where(c =>
                c.UseCases.Contains("Privilege Escalation") ||
                !c.FilterResults.ContainsKey("PrivDelta") ||
                c.FilterResults["PrivDelta"] == FilterResult.Passed)
                .ToList();

            if (remaining.Count < beforePrivFilter)
                AnsiConsole.MarkupLine($"  [yellow]Removed {beforePrivFilter - remaining.Count} " +
                    "same-privilege candidates (profile setting)[/]");
        }

        // NOTE: Target filtering is handled upstream in StaticDiscoveryEngine.FilterByTarget()
        // No redundant target filter here — avoids loose Contains() matching issues.

        AnsiConsole.MarkupLine(
            $"[bold green]Pipeline complete: {initialCount} → {remaining.Count} candidates[/]");
        ScanLogger.Debug($"Filter pipeline complete: {initialCount} → {remaining.Count} candidates");

        return remaining;
    }

    private static List<HijackCandidate> Deduplicate(List<HijackCandidate> candidates)
    {
        return candidates
            .GroupBy(c =>
            {
                // EnvPath candidates are PATH-directory hijacks: the attack is the (dll, dir)
                // slot, not any specific binary that happens to load that dll. Grouping by
                // (dll, path) collapses hundreds of per-binary duplicates into one finding
                // while keeping the highest-priority trigger (service > task > …) in the group.
                if (c.Type == HijackType.EnvPath)
                    return $"ENVPATH|{c.DllName}|{c.HijackWritablePath}";
                return $"{c.BinaryPath}|{c.DllName}|{c.HijackWritablePath}";
            }, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(c => c.Confidence)
                         .ThenByDescending(c => GetTriggerPriority(c.Trigger))
                         .First())
            .ToList();
    }

    private static int GetTriggerPriority(TriggerType t) => t switch
    {
        TriggerType.Service => 10,
        TriggerType.ScheduledTask => 8,
        TriggerType.Startup => 7,
        TriggerType.RunKey => 6,
        TriggerType.COM => 5,
        _ => 1
    };
}