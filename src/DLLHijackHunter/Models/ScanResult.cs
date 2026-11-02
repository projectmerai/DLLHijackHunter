namespace DLLHijackHunter.Models;

public class ScanResult
{
    public string Hostname { get; set; } = Environment.MachineName;
    public string OSVersion { get; set; } = Environment.OSVersion.ToString();
    public DateTime ScanDate { get; set; } = DateTime.UtcNow;
    public string ScanMode { get; set; } = "";
    public string ProfileUsed { get; set; } = "";
    public TimeSpan ScanDuration { get; set; }

    // Counts
    public int TotalCandidatesDiscovered { get; set; }
    public int EliminatedByFilters { get; set; }
    public int SurvivedSoftGates { get; set; }

    // Results by tier
    public List<HijackCandidate> Confirmed { get; set; } = new();
    public List<HijackCandidate> High { get; set; } = new();
    public List<HijackCandidate> Medium { get; set; } = new();
    public List<HijackCandidate> Low { get; set; } = new();
    // Below the Low tier (<20% confidence) but above the profile's MinConfidence — e.g. the
    // aggressive profile's 15% threshold or an explicit --min-confidence below 20.
    public List<HijackCandidate> Informational { get; set; } = new();

    public List<HijackCandidate> AllFindings =>
        Confirmed.Concat(High).Concat(Medium).Concat(Low).Concat(Informational)
                 .OrderByDescending(c => c.FinalScore).ToList();

    public int TotalFindings =>
        Confirmed.Count + High.Count + Medium.Count + Low.Count + Informational.Count;

    // Attack chain analysis
    public List<AttackChain> AttackChains { get; set; } = new();
}