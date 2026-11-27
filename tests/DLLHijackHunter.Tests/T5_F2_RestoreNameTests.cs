using System.Security.Cryptography;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// F2: an existing file the canary backs up and replaces comes back under its exact on-disk name, with the same
/// SHA-256, size and mtime; a mismatch after restore is residue. Temp dir only.
/// </summary>
public sealed class T5_F2_RestoreNameTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hh-t5f2-").FullName;
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static readonly DateTime OriginalMtime = new(2025, 2, 20, 15, 37, 0, DateTimeKind.Utc);

    /// <summary>Real file operations; reboot scheduling is only recorded; optionally a restore that alters mtime.</summary>
    private sealed class TestFileOps : RealFileOps
    {
        public bool TouchAfterMove;
        public override bool ScheduleDeleteOnReboot(string path) => true;
        public override bool ScheduleMoveOnReboot(string source, string dest) => true;
        public override void Move(string source, string dest, bool overwrite)
        {
            base.Move(source, dest, overwrite);
            if (TouchAfterMove) File.SetLastWriteTimeUtc(dest, DateTime.UtcNow);   // forced mismatch
        }
    }

    private (string onDiskPath, string deployPath, string sha, long size) MakeOriginal()
    {
        string onDisk = Path.Combine(_dir, "Foo.dll");                 // vendor spelling
        var bytes = new byte[4096]; new Random(47962).NextBytes(bytes);
        File.WriteAllBytes(onDisk, bytes);
        File.SetLastWriteTimeUtc(onDisk, OriginalMtime);
        // The candidate's path is built from the lower-case DllName, as the scanner does.
        return (onDisk, Path.Combine(_dir, "foo.dll"), Convert.ToHexString(SHA256.HashData(bytes)), bytes.Length);
    }

    private string[] Listing() => Directory.GetFileSystemEntries(_dir).Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal).ToArray()!;

    /// <summary>The canary engine's sequence for a position that already holds a file.</summary>
    private async Task<ResidueEntry?> BackupPlantRestore(IFileOps fs, string deploy, List<string> audit)
    {
        var rec = OriginalFile.Capture(fs, deploy)!;
        string backup = deploy + ".hijackhunter.bak";
        fs.Copy(deploy, backup, true);                                  // file-backed-up
        string canary = Path.Combine(_dir, "canary.bin");
        File.WriteAllBytes(canary, new byte[] { 0x4D, 0x5A, 1, 2, 3 });
        fs.Copy(canary, deploy, true);                                  // file-planted (over the original)
        File.Delete(canary);
        var left = await ArtifactCleaner.RemoveAsync(deploy, ArtifactRole.Canary, null, "c1", fs, null,
            new CleanupOptions { Attempts = 1 }, (a, t, r) => audit.Add($"{a} {t} {r}"));
        Assert.Null(left);
        return await OriginalFile.RestoreAndVerifyAsync(backup, rec, "c1", fs, null, new CleanupOptions { Attempts = 1 },
            (a, t, r) => audit.Add($"{a} {t} {r}"));
    }

    [Fact]
    public async Task MixedCaseOriginal_RestoredUnderItsExactName_HashSizeMtimeIdentical()
    {
        var (onDisk, deploy, sha, size) = MakeOriginal();
        var audit = new List<string>();
        var residue = await BackupPlantRestore(new TestFileOps(), deploy, audit);

        Assert.Null(residue);
        Assert.Equal(new[] { "Foo.dll" }, Listing());                  // ordinal: the name's case is identical
        Assert.Equal(sha, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(onDisk))));
        Assert.Equal(size, new FileInfo(onDisk).Length);
        Assert.Equal(OriginalMtime, File.GetLastWriteTimeUtc(onDisk));
    }

    [Fact]
    public async Task ForcedMismatchAfterRestore_IsResidue()
    {
        var (_, deploy, _, _) = MakeOriginal();
        var audit = new List<string>();
        var residue = await BackupPlantRestore(new TestFileOps { TouchAfterMove = true }, deploy, audit);

        Assert.NotNull(residue);
        Assert.Equal(ArtifactRole.Backup, residue!.Role);
        Assert.Contains("mtime", residue.Reason);
        Assert.Contains(audit, a => a.StartsWith("file-restore-verified") && a.Contains("MISMATCH"));
    }
}
