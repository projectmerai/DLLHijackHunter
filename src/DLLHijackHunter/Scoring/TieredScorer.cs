using DLLHijackHunter.Models;

namespace DLLHijackHunter.Scoring;

public class TieredScorer
{
    public void ScoreAll(List<HijackCandidate> candidates)
    {
        foreach (var c in candidates)
        {
            Score(c);
        }
    }

    public void Score(HijackCandidate c)
    {
        // ═══ Canary result adjustments ═══
        if (c.CanaryResult == CanaryResult.Fired)
        {
            c.Confidence = 100.0;
        }
        else if (c.CanaryResult == CanaryResult.Failed)
        {
            c.Confidence -= 20;
        }
        else if (c.CanaryResult == CanaryResult.Timeout)
        {
            c.Confidence -= 10;
        }
        // NotTested = no change (but UAC bypass gets a bonus for inherent reliability)
        if (c.CanaryResult == CanaryResult.NotTested && c.Trigger == TriggerType.UACBypass)
        {
            c.Confidence += 10;
        }

        // ═══ Knowledge Base Boost ═══
        if (c.IsKnownVulnerability)
        {
            c.Confidence += 15; // Massive boost for known public vulnerabilities
            if (!c.UseCases.Contains("Documented Exploit (HijackLibs)"))
                c.UseCases.Add("Documented Exploit (HijackLibs)");
        }

        // ═══ Load-order verification adjustments ═══
        // A verified win (the real loader picks the writable position) is a strong corroboration;
        // a loss to a protected DLL (KnownDLL/System32/SxS) is a strong false-positive signal.
        if (c.LoadProbe == LoadProbeResult.Wins)
            c.Confidence += 10;
        else if (c.LoadProbe == LoadProbeResult.LosesToProtected)
            c.Confidence -= 40;

        c.Confidence = Math.Clamp(c.Confidence, 0.0, 100.0);

        // ═══ Reserve High/Confirmed for verified or corroborated findings ═══
        // A clean static search-order match is a *discovery* signal, not proof. Without
        // a corroborating signal — a fired canary, an ETW runtime load observation, or a
        // documented HijackLibs match — a candidate is capped at the top of the Medium
        // tier so unverified heuristics never present as High confidence.
        bool hasProof = c.CanaryResult == CanaryResult.Fired
            || c.IsKnownVulnerability
            || c.LoadProbe == LoadProbeResult.Wins
            || string.Equals(c.DiscoverySource, "etw", StringComparison.OrdinalIgnoreCase);
        if (!hasProof && c.Confidence > 79.0)
        {
            c.Confidence = 79.0;
            if (!c.Notes.Any(n => n.Contains("Static-only", StringComparison.OrdinalIgnoreCase)))
                c.Notes.Add("Static-only: capped below High pending verification (canary/ETW/KB)");
        }

        // ═══ Determine tier ═══
        c.Tier = c.CanaryResult == CanaryResult.Fired ? ConfidenceTier.Confirmed :
                 c.Confidence >= 80 ? ConfidenceTier.High :
                 c.Confidence >= 50 ? ConfidenceTier.Medium :
                 c.Confidence >= 20 ? ConfidenceTier.Low :
                 ConfidenceTier.Informational;

        // ═══ Impact score (separate from confidence) ═══
        c.ImpactScore = CalculateImpact(c);

        // ═══ Final score = weighted combination ═══
        c.FinalScore = (c.Confidence / 100.0 * 0.4 + c.ImpactScore / 10.0 * 0.6) * 10.0;
        c.FinalScore = Math.Round(Math.Clamp(c.FinalScore, 0, 10), 1);

        // ═══ Add use cases if not already present ═══
        const string UacUseCase = "Silent UAC Bypass (Admin execution without prompt)";
        if (c.Trigger == TriggerType.UACBypass && !c.UseCases.Contains(UacUseCase))
            c.UseCases.Add(UacUseCase);

        const string SideLoadUseCase = "Copy & Side-Load (Copy EXE to writable folder, drop DLL next to it)";
        if (c.IsSimulatedCopyAttack && !c.UseCases.Contains(SideLoadUseCase))
            c.UseCases.Add(SideLoadUseCase);
            
        if (c.SurvivesReboot && !c.UseCases.Contains("Persistence"))
            c.UseCases.Add("Persistence");

        if (c.Type == HijackType.Phantom && !c.UseCases.Contains("Clean Hijack (no file replaced)"))
            c.UseCases.Add("Clean Hijack (no file replaced)");
    }

    private static double CalculateImpact(HijackCandidate c)
    {
        double impact = 0;

        // Privilege gained (0-4)
        string runAs = c.ConfirmedPrivilege ?? c.RunAsAccount;
        string upper = runAs.ToUpperInvariant();

        if (upper is "NT AUTHORITY\\SYSTEM" or "NT AUTHORITY\\\\SYSTEM" or "LOCALSYSTEM")
            impact += 4.0;
        else if (upper.StartsWith("HIGH_INTEGRITY") ||
                 upper.EndsWith("\\ADMINISTRATOR") || upper.EndsWith("\\\\ADMINISTRATOR") ||
                 upper is "NT AUTHORITY\\LOCAL SERVICE" or "NT AUTHORITY\\\\LOCAL SERVICE" or
                 "NT AUTHORITY\\NETWORK SERVICE" or "NT AUTHORITY\\\\NETWORK SERVICE")
            impact += 3.0;
        else
            impact += 1.0;

        // Trigger reliability (0-3)
        impact += c.Trigger switch
        {
            TriggerType.Service when c.ServiceStartType == "AUTO_START" => 3.0,
            TriggerType.ScheduledTask when c.TaskFrequency < TimeSpan.FromHours(1) => 2.5,
            TriggerType.UACBypass => 2.8,
            TriggerType.Startup or TriggerType.RunKey => 2.0,
            TriggerType.Service => 1.5,
            TriggerType.COM => 1.0,
            _ => 0.5
        };

        // Stealth (0-2)
        impact += c.Type switch
        {
            HijackType.Phantom => 2.0,
            HijackType.DotLocal => 1.8,
            HijackType.SearchOrder => 1.5,
            HijackType.SideLoad => 1.5,
            HijackType.EnvPath => 2.0,
            _ => 1.0
        };

        // Persistence bonus
        if (c.SurvivesReboot) impact += 1.0;

        return Math.Clamp(impact, 0, 10);
    }
}