using DLLHijackHunter.Models;

namespace DLLHijackHunter.Filters;

/// <summary>
/// SOFT GATE: Does this hijack give the attacker MORE privilege?
/// Same-privilege hijacks are still useful for persistence/evasion.
/// Penalty: 15% for same-privilege (not useless, just different use case).
/// </summary>
public class PrivilegeDeltaFilter : ISoftGate
{
    public string Name => "Privilege Escalation Delta";

    // The attacker is always modelled as an unprivileged, medium-integrity standard user —
    // the same baseline AclChecker uses (hardcoded Users / Authenticated Users / Everyone
    // SIDs). Comparing against the scanner's own token would make every result depend on
    // whether the tool happened to be run elevated (High = 3), turning LOCAL SERVICE /
    // UAC-bypass targets into "same privilege" and standard-user targets into "lower".
    private const int AttackerBaselinePrivLevel = 2;

    public (double penalty, string? reason) Evaluate(HijackCandidate candidate)
    {
        int targetPrivLevel = GetTargetPrivilegeLevel(candidate.RunAsAccount);

        if (targetPrivLevel > AttackerBaselinePrivLevel)
        {
            // Privilege escalation — no penalty
            if (!candidate.UseCases.Contains("Privilege Escalation"))
                candidate.UseCases.Add("Privilege Escalation");
            candidate.FilterResults["PrivDelta"] = FilterResult.Passed;
            return (0, null);
        }

        if (targetPrivLevel == AttackerBaselinePrivLevel)
        {
            // Same privilege — still useful for persistence and evasion
            if (!candidate.UseCases.Contains("Persistence"))
                candidate.UseCases.Add("Persistence");
            if (!candidate.UseCases.Contains("Defense Evasion"))
                candidate.UseCases.Add("Defense Evasion");

            // If target is a signed binary, it's great for EDR bypass
            try
            {
                var pe = Discovery.PEAnalyzer.Analyze(candidate.BinaryPath);
                if (pe.IsSigned)
                {
                    if (!candidate.UseCases.Contains("EDR Bypass (signed binary injection)"))
                        candidate.UseCases.Add("EDR Bypass (signed binary injection)");
                    if (!candidate.UseCases.Contains("Application Whitelisting Bypass"))
                        candidate.UseCases.Add("Application Whitelisting Bypass");
                }
            }
            catch { }

            candidate.FilterResults["PrivDelta"] = FilterResult.Failed;
            return (15, $"Same privilege level (target={candidate.RunAsAccount}, " +
                       "attacker=StandardUser). " +
                       "Still useful for persistence/evasion.");
        }

        // Target runs at LOWER privilege — minimal value
        candidate.FilterResults["PrivDelta"] = FilterResult.Failed;
        return (30, $"Target runs at lower privilege than the attacker (attacker=StandardUser)");
    }

    private static int GetTargetPrivilegeLevel(string runAsAccount)
    {
        string upper = runAsAccount.ToUpperInvariant();

        // Exact known service accounts
        if (upper is "NT AUTHORITY\\SYSTEM" or "NT AUTHORITY\\\\SYSTEM" or "LOCALSYSTEM")
            return 4;
        if (upper is "NT AUTHORITY\\LOCAL SERVICE" or "NT AUTHORITY\\\\LOCAL SERVICE" or
            "NT AUTHORITY\\NETWORK SERVICE" or "NT AUTHORITY\\\\NETWORK SERVICE")
            return 3;

        // UAC elevated context (High integrity, same user)
        if (upper.StartsWith("HIGH_INTEGRITY"))
            return 3;

        // Built-in admin groups (exact prefix, not substring)
        if (upper.EndsWith("\\ADMINISTRATOR") || upper.EndsWith("\\\\ADMINISTRATOR") ||
            upper is "BUILTIN\\ADMINISTRATORS" or "BUILTIN\\\\ADMINISTRATORS")
            return 3;

        return 2; // standard user
    }
}