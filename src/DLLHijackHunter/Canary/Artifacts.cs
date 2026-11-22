using DLLHijackHunter.Models;

namespace DLLHijackHunter.Canary;

public sealed class ArtifactEntry
{
    public string Path { get; set; } = "";
    public ArtifactRole Role { get; set; }
    public string? Sha256 { get; set; }
    public string ScanId { get; set; } = "";
    public string? CandidateId { get; set; }
    public string? RestoreTo { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

// 9c91eab had no artifact manifest, sweep, cleanup retry or canary marker check.
public sealed class ArtifactManifest
{
    public static string DefaultPath => throw new NotImplementedException("not in 9c91eab");
    public static ArtifactManifest? Current { get; set; }
    public ArtifactManifest(string path, bool requireTrustedFile = true) => FilePath = path;
    public string FilePath { get; }
    public bool Trusted => false;
    public string? LoadProblem => null;
    public IReadOnlyList<ArtifactEntry> Entries => throw new NotImplementedException("not in 9c91eab");
    public void Add(ArtifactEntry e) => throw new NotImplementedException("not in 9c91eab");
    public bool Remove(string path) => throw new NotImplementedException("not in 9c91eab");
    public ArtifactEntry? Find(string path) => throw new NotImplementedException("not in 9c91eab");
}

public interface IFileOps
{
    bool Exists(string path);
    void Delete(string path);
    void Move(string source, string dest, bool overwrite);
    void Copy(string source, string dest, bool overwrite);
    string? Sha256(string path);
    bool ScheduleDeleteOnReboot(string path);
    bool ScheduleMoveOnReboot(string source, string dest);
    string? FindLockHolders(string path);
}

public class RealFileOps : IFileOps
{
    public virtual bool Exists(string path) => File.Exists(path);
    public virtual void Delete(string path) => File.Delete(path);
    public virtual void Move(string source, string dest, bool overwrite) => File.Move(source, dest, overwrite);
    public virtual void Copy(string source, string dest, bool overwrite) => File.Copy(source, dest, overwrite);
    public virtual string? Sha256(string path) => throw new NotImplementedException("not in 9c91eab");
    public virtual bool ScheduleDeleteOnReboot(string path) => throw new NotImplementedException("not in 9c91eab");
    public virtual bool ScheduleMoveOnReboot(string source, string dest) => throw new NotImplementedException("not in 9c91eab");
    public virtual string? FindLockHolders(string path) => throw new NotImplementedException("not in 9c91eab");
}

public sealed class CleanupOptions
{
    public int Attempts { get; init; } = 5;
    public Func<int, TimeSpan> Backoff { get; init; } = attempt => TimeSpan.FromMilliseconds(250 * attempt);
}

public static class ArtifactSweeper
{
    public static List<SweepItem> Sweep(ArtifactManifest manifest, IFileOps fs, List<ResidueEntry> residue) =>
        throw new NotImplementedException("not in 9c91eab");
}

public static class ArtifactCleaner
{
    public static Task<ResidueEntry?> RemoveAsync(string path, ArtifactRole role, string? sha256,
        string? candidateId, IFileOps fs, Func<Task>? stopTrigger, CleanupOptions? options = null,
        Action<string, string, string>? audit = null) =>
        throw new NotImplementedException("not in 9c91eab");

    public static Task<ResidueEntry?> RestoreAsync(string backupPath, string targetPath, string? sha256,
        string? candidateId, IFileOps fs, Func<Task>? stopTrigger, CleanupOptions? options = null,
        Action<string, string, string>? audit = null) =>
        throw new NotImplementedException("not in 9c91eab");
}

public static class CanaryMarker
{
    public const string CanaryString = "[DllHijackHunter] precompiled canary fired";
    public const string ProxyString = "DLLHijackHunter-runtime-proxy-canary";
    public static bool HasMarker(ReadOnlySpan<byte> bytes) => false;
    public static bool FileHasMarker(string path) => false;
}

public static class ArtifactPaths
{
    public static bool IsToolArtifact(string path, ArtifactManifest? manifest) => false;
}

public enum DeployPathKind { Absent, Original, ToolArtifact }
