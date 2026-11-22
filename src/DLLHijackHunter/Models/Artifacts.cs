namespace DLLHijackHunter.Models;

/// <summary>Role of a file DLLHijackHunter places on the machine.</summary>
public enum ArtifactRole
{
    Canary,   // canary / probe DLL at a deploy position, or a canary build in the tool's own folder
    Sidecar,  // copy of the original DLL that a proxy canary forwards to
    Backup,   // copy of an original DLL taken before it was replaced
    Confirm   // confirmation file a canary writes when it fires
}

/// <summary>A file the tool placed and could not remove (or restore).</summary>
public class ResidueEntry
{
    public string Path { get; set; } = "";
    public ArtifactRole Role { get; set; }
    public string? Sha256 { get; set; }
    // Processes holding the file open, from the Restart Manager ("name (PID n)"), when known.
    public string? Holder { get; set; }
    // MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) was scheduled for it.
    public bool DelayedDeleteScheduled { get; set; }
    public string? CandidateId { get; set; }
    public string Reason { get; set; } = "";
}

/// <summary>Outcome of the startup sweep for one manifest entry left by a previous run.</summary>
public class SweepItem
{
    public string Path { get; set; } = "";
    public ArtifactRole Role { get; set; }
    // Deleted | Restored | AlreadyGone | HashMismatchLeftAlone | RestoreTargetOccupied | DeleteFailed | RestoreFailed
    public string Outcome { get; set; } = "";
    public string? ScanId { get; set; }
    public string Detail { get; set; } = "";
}
