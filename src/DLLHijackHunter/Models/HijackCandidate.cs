namespace DLLHijackHunter.Models;

public enum HijackType
{
    Phantom,        // DLL doesn't exist anywhere on disk
    SearchOrder,    // DLL exists but attacker can place one earlier in search order
    SideLoad,       // DLL loaded by legitimate app from its own directory
    DotLocal,       // .local file redirection
    EnvPath,        // Writable directory in PATH environment variable
    AppInitDll,     // AppInit_DLLs registry abuse
    AppCertDll      // AppCertDLLs registry abuse
}

public enum TriggerType
{
    Service,
    ScheduledTask,
    Startup,
    COM,
    RunKey,
    Manual,
    UACBypass,
    Unknown
}

public enum FilterResult
{
    Passed,
    Failed,
    Skipped,
    NotTested
}

public enum CanaryResult
{
    NotTested,
    Fired,
    Failed,
    Timeout,
    Blocked
}

public enum LoadProbeResult
{
    NotRun,           // Probe disabled or not applicable
    Skipped,          // Candidate type not faithfully representable by the probe
    Wins,             // The writable position wins the loader's search (resolution verified)
    LosesToProtected, // A protected DLL (KnownDLL/System32/SxS) wins instead — likely false positive
    NotResolved,      // The name did not resolve even with the probe placed
    Error             // Probe could not run (child failure, file locked, etc.)
}

public enum ConfidenceTier
{
    Confirmed,   // Canary-proven, 100% exploitable
    High,        // 80–100% confidence
    Medium,      // 50–79% confidence
    Low,         // 20–49% confidence
    Informational // <20% but still worth knowing
}

public enum AnalysisConfidence
{
    Certain,         // Direct constant in instruction
    CertainDirect,   // Direct call with known flag
    IndirectCall,    // Call through register/pointer
    Unknown          // Could not determine
}

public class HijackCandidate
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    // ─── Identity ───
    public string BinaryPath { get; set; } = "";
    // Short image name (e.g. "app.exe") when ETW could not resolve the full path. BinaryPath is
    // then empty, never a bare name. Null when the path is known.
    public string? BinaryImageName { get; set; }
    public string DllName { get; set; } = "";
    public string? DllLegitPath { get; set; }

    // ─── Classification ───
    public HijackType Type { get; set; }
    public string HijackWritablePath { get; set; } = "";

    // ─── Trigger context ───
    public TriggerType Trigger { get; set; } = TriggerType.Unknown;
    public string TriggerIdentifier { get; set; } = "";
    public bool IsSimulatedCopyAttack { get; set; } // Attacker copies EXE to writable folder
    public string RunAsAccount { get; set; } = "";
    public string? ServiceStartType { get; set; }
    public TimeSpan? TaskFrequency { get; set; }

    // ─── Filter results ───
    public Dictionary<string, FilterResult> FilterResults { get; set; } = new();

    // ─── Soft gate analysis details ───
    public bool ManifestCoversThisSpecificDll { get; set; }
    public AnalysisConfidence LoadLibAnalysisConfidence { get; set; } = AnalysisConfidence.Unknown;
    public bool IsProtectedProcess { get; set; }

    // ─── Load-order verification (opt-in --verify-load) ───
    public LoadProbeResult LoadProbe { get; set; } = LoadProbeResult.NotRun;
    public string? LoadProbeResolvedPath { get; set; }

    // ─── Canary confirmation ───
    public CanaryResult CanaryResult { get; set; } = CanaryResult.NotTested;
    public string? ConfirmedPrivilege { get; set; }
    public string? ConfirmedIntegrityLevel { get; set; }
    public bool? ConfirmedSeDebug { get; set; }
    public bool AppStillFunctional { get; set; } = true;
    // Why a Failed canary failed when the cause is the harness rather than the hijack
    // (see CanaryFailureCauses). Null otherwise. A harness cause carries no scoring penalty.
    public string? CanaryFailureCause { get; set; }
    // Ordered audit trail of every side effect the canary and its triggers caused for this candidate.
    public List<CanaryAction> CanaryActions { get; set; } = new();

    // ─── Scoring ───
    public ConfidenceTier Tier { get; set; } = ConfidenceTier.Informational;
    public double Confidence { get; set; }
    public double ImpactScore { get; set; }
    public double FinalScore { get; set; }
    public bool SurvivesReboot { get; set; }

    // ─── Knowledge Base Integration ───
    public bool IsKnownVulnerability { get; set; }
    public string? KnowledgeBaseReference { get; set; }

    // ─── Metadata ───
    public List<string> UseCases { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    public string DiscoverySource { get; set; } = "static"; // "static", "etw" or "companion"
    // Companion findings: the service whose companion executable this is, and whether ETW saw the
    // executable run during this scan (which lifts the Medium cap).
    public string? CompanionOf { get; set; }
    public bool CompanionObserved { get; set; }
    // ETW findings: the PID (and process start time, when known) of the process that made the lookup.
    public int? ObservedPid { get; set; }
    public DateTime? ObservedProcessStartUtc { get; set; }
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;

    public override string ToString() =>
        $"[{Tier}] {BinaryPath} → {DllName} ({Type}) via {Trigger} as {RunAsAccount} " +
        $"[Confidence={Confidence:F0}% Impact={ImpactScore:F1}]";
}

/// <summary>One side effect on the machine, in the order it happened (audit trail).</summary>
public class CanaryAction
{
    public DateTime Utc { get; set; } = DateTime.UtcNow;
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
    public string Result { get; set; } = "";
}

/// <summary>Harness causes recorded in <see cref="HijackCandidate.CanaryFailureCause"/>.</summary>
public static class CanaryFailureCauses
{
    public const string CouldNotTrigger = "could-not-trigger";
    public const string CouldNotBackUp = "could-not-back-up";
    public const string CouldNotStageSidecar = "could-not-stage-sidecar";
    public const string TargetDirectoryMissing = "target-directory-missing";
}