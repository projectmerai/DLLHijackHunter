using DLLHijackHunter.Models;

namespace DLLHijackHunter.Canary;

/// <summary>
/// Per-run side-effect accounting shared by the canary, the load probe and reporting: the scan
/// ID, the artifact manifest, file operations, residue and the startup sweep's report.
/// </summary>
public static class ScanSession
{
    private static readonly object _lock = new();
    private static readonly List<ResidueEntry> _residue = new();

    public static string ScanId { get; private set; } = Guid.NewGuid().ToString("N")[..12];
    public static IFileOps Files { get; set; } = new RealFileOps();
    public static List<SweepItem> Sweep { get; } = new();

    public static ArtifactManifest? Manifest => ArtifactManifest.Current;

    /// <summary>Open the manifest and sweep what a previous run left. Called once, before discovery.</summary>
    public static void Begin(string? manifestPath = null)
    {
        ScanId = Guid.NewGuid().ToString("N")[..12];
        try
        {
            ArtifactManifest.Current = new ArtifactManifest(manifestPath ?? ArtifactManifest.DefaultPath);
        }
        catch (Exception ex)
        {
            ScanLogger.Warn($"Artifact manifest unavailable: {ex.Message}");
            ArtifactManifest.Current = null;
            return;
        }

        var m = ArtifactManifest.Current;
        if (m.LoadProblem != null) ScanLogger.Warn(m.LoadProblem);
        if (m.Entries.Count == 0) return;

        var residue = new List<ResidueEntry>();
        var items = ArtifactSweeper.Sweep(m, Files, residue);
        lock (_lock)
        {
            Sweep.AddRange(items);
            foreach (var r in residue) AddResidueLocked(r);
        }
        foreach (var i in items)
            Safety.Audit.Record("startup-sweep", null, "sweep-" + i.Outcome, i.Path,
                $"role={i.Role} scan={i.ScanId} {i.Detail}".TrimEnd());
    }

    /// <summary>Record a manifest entry before placing a file. False when it cannot be recorded.</summary>
    public static bool TryRecord(ArtifactEntry entry, out string? error)
    {
        error = null;
        var m = Manifest;
        if (m == null) { error = "artifact manifest unavailable"; return false; }
        entry.ScanId = ScanId;
        try
        {
            m.Add(entry);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>Drop the manifest entry once the file is verified gone / restored.</summary>
    public static void Forget(string path)
    {
        try { Manifest?.Remove(path); }
        catch (Exception ex) { ScanLogger.Warn($"Could not update artifact manifest for {path}: {ex.Message}"); }
    }

    public static void AddResidue(ResidueEntry entry)
    {
        lock (_lock) AddResidueLocked(entry);
    }

    private static void AddResidueLocked(ResidueEntry entry)
    {
        int i = _residue.FindIndex(r => ArtifactManifest.PathsEqual(r.Path, entry.Path));
        if (i >= 0)
        {
            // Keep the most informative record for a path.
            var old = _residue[i];
            entry.Holder ??= old.Holder;
            entry.DelayedDeleteScheduled |= old.DelayedDeleteScheduled;
            _residue[i] = entry;
        }
        else _residue.Add(entry);
    }

    public static List<ResidueEntry> Residue
    {
        get { lock (_lock) return _residue.ToList(); }
    }
}
