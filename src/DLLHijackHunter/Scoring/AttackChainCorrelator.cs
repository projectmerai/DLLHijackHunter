using DLLHijackHunter.Models;
using System.Security.Principal;

namespace DLLHijackHunter.Scoring;

public class AttackChainCorrelator
{
    public List<AttackChain> BuildChains(List<HijackCandidate> findings)
    {
        var chains = new List<AttackChain>();

        // 1. Categorize findings
        var uacBypasses = findings.Where(c => c.Trigger == TriggerType.UACBypass).ToList();

        // Every finding has already passed the WritabilityFilter, which judges writability
        // for an UNPRIVILEGED principal (AclChecker). So any SYSTEM finding — EnvPath,
        // SearchOrder, Phantom, DotLocal — is directly plantable by a standard user.
        var systemFindings = findings.Where(c =>
            (c.RunAsAccount.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
             c.RunAsAccount.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) ||
             c.ConfirmedPrivilege?.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) == true) &&
            c.Trigger != TriggerType.UACBypass &&
            !c.IsProtectedProcess).ToList();

        // 2. "The Direct Path" (User -> SYSTEM)
        if (systemFindings.Any())
        {
            var bestDirect = systemFindings.OrderByDescending(c => c.FinalScore).First();
            chains.Add(new AttackChain
            {
                Name = "The Direct Path (User → SYSTEM)",
                Description = "A standard user can plant a DLL that a SYSTEM process loads.",
                TargetPrivilege = "NT AUTHORITY\\SYSTEM",
                Steps = new List<AttackStep>
                {
                    new() { StepNumber = 1, Action = "Start as Standard User", Details = "No administrative rights required." },
                    new() { StepNumber = 2, Action = $"Plant malicious {bestDirect.DllName}", Details = $"Write payload to: {bestDirect.HijackWritablePath}", Finding = bestDirect },
                    new() { StepNumber = 3, Action = $"Trigger: {bestDirect.TriggerIdentifier}", Details = bestDirect.SurvivesReboot ? "Wait for reboot or service start." : "Execute trigger." },
                    new() { StepNumber = 4, Action = "💥 SYSTEM Shell Achieved!", Details = "Bypassed Admin entirely." }
                }
            });
        }

        // 3. "The Ladder" (User -> Admin -> SYSTEM): only meaningful when there is NO direct
        //    SYSTEM hijack. A silent UAC bypass yields a High-Integrity admin token, from which
        //    SYSTEM is a standard administrative step — not dependent on another finding.
        if (uacBypasses.Any() && !systemFindings.Any())
        {
            var bestUac = uacBypasses.OrderByDescending(c => c.FinalScore).First();

            chains.Add(new AttackChain
            {
                Name = "The Ladder (User → Admin → SYSTEM)",
                Description = "Chains a silent UAC bypass (as a member of Administrators running at " +
                              "medium integrity) into a High-Integrity token, then SYSTEM.",
                TargetPrivilege = "NT AUTHORITY\\SYSTEM",
                Steps = new List<AttackStep>
                {
                    new() { StepNumber = 1, Action = "Start as a filtered-token admin (medium integrity)", Details = "UAC bypass requires the user to be in Administrators." },
                    new()
                    {
                        StepNumber = 2,
                        Action = $"Execute Silent UAC Bypass via {bestUac.DllName}",
                        Details = $"Copy {Path.GetFileName(bestUac.BinaryPath)} to writable folder, drop DLL, and execute.",
                        Finding = bestUac
                    },
                    new() { StepNumber = 3, Action = "Achieve High Integrity (Local Admin)", Details = "Full administrative token without a consent prompt." },
                    new() { StepNumber = 4, Action = "💥 Escalate to SYSTEM", Details = "Standard admin → SYSTEM step (e.g. create/modify a service)." }
                }
            });
        }

        // 4. Build "Persistence" Chain (Initial Compromise -> AutoStart)
        string currentUser;
        try { currentUser = WindowsIdentity.GetCurrent().Name; }
        catch { currentUser = "Unknown"; }

        var persistanceFindings = findings.Where(c => c.SurvivesReboot && c.Trigger != TriggerType.Service).ToList();
        
        if (persistanceFindings.Any())
        {
            var bestPersistance = persistanceFindings.OrderByDescending(c => c.FinalScore).First();
            chains.Add(new AttackChain
            {
                Name = "The Long Con (User → Persistence)",
                Description = "Establishes a stealthy persistence mechanism that survives reboots.",
                TargetPrivilege = bestPersistance.RunAsAccount ?? currentUser,
                Steps = new List<AttackStep>
                {
                    new() { StepNumber = 1, Action = "Achieve Initial Compromise", Details = "Assume attacker has gained initial access." },
                    new() { StepNumber = 2, Action = $"Plant malicious {bestPersistance.DllName}", Details = $"Write payload to: {bestPersistance.HijackWritablePath}", Finding = bestPersistance },
                    new() { StepNumber = 3, Action = "Wait for Reboot / User Logon", Details = "The DLL will be automatically loaded." },
                    new() { StepNumber = 4, Action = "💥 Persistent Shell Achieved!", Details = $"Running as {bestPersistance.RunAsAccount ?? "the logged-in user"} every time the system starts." }
                }
            });
        }

        return chains;
    }
}