using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Models;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>S3: canary artifacts are tracked, verified, and never silently left behind. Temp dir only.</summary>
public sealed class S3_ArtifactTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hh-s3-").FullName;
    private string ManifestPath => Path.Combine(_dir, "artifacts.json");

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private static string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b));

    private string WriteFile(string name, byte[] content)
    {
        string p = Path.Combine(_dir, name);
        File.WriteAllBytes(p, content);
        return p;
    }

    /// <summary>Real file operations, except that reboot-time scheduling is only recorded.</summary>
    private sealed class RecordingFileOps : RealFileOps
    {
        public List<string> ScheduledDeletes { get; } = new();
        public override bool ScheduleDeleteOnReboot(string path) { ScheduledDeletes.Add(path); return true; }
        public override bool ScheduleMoveOnReboot(string source, string dest) { ScheduledDeletes.Add(source + "->" + dest); return true; }
    }

    [Fact]
    public void Manifest_RoundTrip()
    {
        var m = new ArtifactManifest(ManifestPath, requireTrustedFile: false);
        m.Add(new ArtifactEntry { Path = @"C:\w\helper.dll", Role = ArtifactRole.Canary, Sha256 = "AA", ScanId = "s1", CandidateId = "c1" });
        m.Add(new ArtifactEntry { Path = @"C:\w\helper_hhorig.dll", Role = ArtifactRole.Sidecar, Sha256 = "BB", ScanId = "s1", CandidateId = "c1" });
        m.Add(new ArtifactEntry { Path = @"C:\w\helper.dll.hijackhunter.bak", Role = ArtifactRole.Backup, Sha256 = "CC", ScanId = "s1", CandidateId = "c1", RestoreTo = @"C:\w\helper.dll" });

        var reloaded = new ArtifactManifest(ManifestPath, requireTrustedFile: false);
        Assert.Equal(3, reloaded.Entries.Count);
        var bak = reloaded.Find(@"C:\W\HELPER.DLL.hijackhunter.bak");
        Assert.NotNull(bak);
        Assert.Equal(ArtifactRole.Backup, bak!.Role);
        Assert.Equal(@"C:\w\helper.dll", bak.RestoreTo);
        Assert.Equal("c1", bak.CandidateId);

        Assert.True(reloaded.Remove(@"C:\w\helper_hhorig.dll"));
        Assert.Equal(2, new ArtifactManifest(ManifestPath, requireTrustedFile: false).Entries.Count);
    }

    [Fact]
    public void Manifest_WriteIsAtomic_TempPlusReplace()
    {
        // A stale temp file from an interrupted write must not be read or left to grow.
        File.WriteAllText(ManifestPath + ".deadbeef.tmp", "{ truncated");
        var m = new ArtifactManifest(ManifestPath, requireTrustedFile: false);
        for (int i = 0; i < 20; i++)
            m.Add(new ArtifactEntry { Path = $@"C:\w\{i}.dll", Role = ArtifactRole.Canary, Sha256 = "00", ScanId = "s" });

        // Only the stale temp file remains next to the manifest: every write went through
        // a temp file that replaced the manifest.
        var leftovers = Directory.GetFiles(_dir, "artifacts.json.*.tmp");
        Assert.Single(leftovers);
        using var doc = JsonDocument.Parse(File.ReadAllText(ManifestPath));   // complete, valid JSON
        Assert.Equal(20, new ArtifactManifest(ManifestPath, requireTrustedFile: false).Entries.Count);
    }

    [Fact]
    public void Sweep_DeletesHashMatchedLeftover()
    {
        byte[] content = Encoding.ASCII.GetBytes("MZ leftover canary " + CanaryMarker.CanaryString);
        string leftover = WriteFile("helper.dll", content);
        var m = new ArtifactManifest(ManifestPath, requireTrustedFile: false);
        m.Add(new ArtifactEntry { Path = leftover, Role = ArtifactRole.Canary, Sha256 = Sha(content), ScanId = "old" });

        var residue = new List<ResidueEntry>();
        var items = ArtifactSweeper.Sweep(new ArtifactManifest(ManifestPath, requireTrustedFile: false),
            new RecordingFileOps(), residue);

        Assert.False(File.Exists(leftover));
        Assert.Equal("Deleted", Assert.Single(items).Outcome);
        Assert.Empty(residue);
        Assert.Empty(new ArtifactManifest(ManifestPath, requireTrustedFile: false).Entries);
    }

    [Fact]
    public void Sweep_LeavesHashMismatchedFileAlone()
    {
        string notOurs = WriteFile("helper.dll", Encoding.ASCII.GetBytes("someone else's DLL"));
        var m = new ArtifactManifest(ManifestPath, requireTrustedFile: false);
        m.Add(new ArtifactEntry { Path = notOurs, Role = ArtifactRole.Canary, Sha256 = Sha(new byte[] { 1, 2, 3 }), ScanId = "old" });

        var items = ArtifactSweeper.Sweep(m, new RecordingFileOps(), new List<ResidueEntry>());

        Assert.True(File.Exists(notOurs));
        Assert.Equal("HashMismatchLeftAlone", Assert.Single(items).Outcome);
    }

    [Fact]
    public void Sweep_RestoresRecordedBackup()
    {
        byte[] original = Encoding.ASCII.GetBytes("original DLL bytes");
        string target = Path.Combine(_dir, "orig.dll");
        string backup = WriteFile("orig.dll.hijackhunter.bak", original);
        var m = new ArtifactManifest(ManifestPath, requireTrustedFile: false);
        m.Add(new ArtifactEntry { Path = backup, Role = ArtifactRole.Backup, Sha256 = Sha(original), ScanId = "old", RestoreTo = target });

        var items = ArtifactSweeper.Sweep(m, new RecordingFileOps(), new List<ResidueEntry>());

        Assert.Equal("Restored", Assert.Single(items).Outcome);
        Assert.Equal(original, File.ReadAllBytes(target));
        Assert.False(File.Exists(backup));
    }

    [Fact]
    public void DeployPath_FileWithCanaryMarker_IsRefusedAsOriginal()
    {
        string leftover = WriteFile("helper.dll",
            Encoding.ASCII.GetBytes("MZ\0\0 ... " + CanaryMarker.CanaryString + " ..."));
        var (kind, reason) = CanaryEngine.ClassifyExistingDeployFile(leftover, null, new RecordingFileOps());
        Assert.Equal(DeployPathKind.ToolArtifact, kind);
        Assert.False(string.IsNullOrEmpty(reason));
    }

    [Fact]
    public void DeployPath_ManifestHashMatch_IsRefusedAsOriginal()
    {
        byte[] bytes = Encoding.ASCII.GetBytes("proxy without a readable marker");
        string p = WriteFile("helper.dll", bytes);
        var m = new ArtifactManifest(ManifestPath, requireTrustedFile: false);
        m.Add(new ArtifactEntry { Path = p, Role = ArtifactRole.Canary, Sha256 = Sha(bytes), ScanId = "old" });
        Assert.Equal(DeployPathKind.ToolArtifact,
            CanaryEngine.ClassifyExistingDeployFile(p, m, new RecordingFileOps()).kind);
    }

    [Fact]
    public void DeployPath_OrdinaryDll_IsOriginal()
    {
        string p = WriteFile("real.dll", Encoding.ASCII.GetBytes("MZ a real vendor DLL"));
        Assert.Equal(DeployPathKind.Original,
            CanaryEngine.ClassifyExistingDeployFile(p, null, new RecordingFileOps()).kind);
    }

    [Fact]
    public void EmbeddedCanaryAndRuntimeProxy_CarryTheMarker()
    {
        Assert.True(CanaryDllBuilder.TryGetEmbeddedCanaryBytes(true, out var x64));
        Assert.True(CanaryMarker.HasMarker(x64));
        Assert.True(CanaryDllBuilder.TryGetEmbeddedCanaryBytes(false, out var x86));
        Assert.True(CanaryMarker.HasMarker(x86));

        var exports = new List<ExportEntry> { new() { Name = "Hello", Ordinal = 1 } };
        Assert.True(RuntimeProxyBuilder.TryBuild(x64, "helper_hhorig", exports, out var proxy));
        Assert.Contains(CanaryMarker.ProxyString, Encoding.ASCII.GetString(proxy));
    }

    [Fact]
    public void ToolArtifactPaths_AreRecognised()
    {
        Assert.True(ArtifactPaths.IsToolArtifact(@"C:\w\helper_hhorig.dll", null));
        Assert.True(ArtifactPaths.IsToolArtifact(@"C:\w\helper_hhorig.DLL", null));
        Assert.True(ArtifactPaths.IsToolArtifact(@"C:\w\helper.dll.hijackhunter.bak", null));
        Assert.True(ArtifactPaths.IsToolArtifact(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"DLLHijackHunter\canary_abc.dll"), null));
        Assert.False(ArtifactPaths.IsToolArtifact(@"C:\w\helper.dll", null));
    }

    [Fact]
    public async Task LockedFileDelete_EndsAsResidue_WithHolderAndDelayedDelete_ExitCode4()
    {
        byte[] content = Encoding.ASCII.GetBytes("canary " + CanaryMarker.CanaryString);
        string canary = WriteFile("locked.dll", content);
        var fs = new RecordingFileOps();
        var audit = new List<string>();
        int stops = 0;

        ResidueEntry? residue;
        using (new FileStream(canary, FileMode.Open, FileAccess.Read, FileShare.Read))  // test holds it open
        {
            residue = await ArtifactCleaner.RemoveAsync(canary, ArtifactRole.Canary, Sha(content), "cand1", fs,
                stopTrigger: () => { stops++; return Task.CompletedTask; },
                new CleanupOptions { Attempts = 5, Backoff = _ => TimeSpan.FromMilliseconds(20) },
                (action, target, result) => audit.Add($"{action}|{result}"));
        }

        Assert.NotNull(residue);
        Assert.Equal(canary, residue!.Path);
        Assert.True(residue.DelayedDeleteScheduled);
        Assert.Contains(canary, fs.ScheduledDeletes);
        Assert.Contains($"PID {Environment.ProcessId}", residue.Holder ?? "");  // Restart Manager names us
        Assert.Equal(1, stops);                                                 // trigger stopped once before retrying
        Assert.Contains(audit, a => a.StartsWith("file-delete-delayed|"));
        Assert.True(File.Exists(canary));                                       // never deleted behind our back

        Assert.Equal(4, Program.ComputeExitCode(0, residueCount: 1));
        Assert.Equal(1, Program.ComputeExitCode(1, residueCount: 1));
        Assert.Equal(3, Program.ComputeExitCode(3, residueCount: 1));
        Assert.Equal(0, Program.ComputeExitCode(0, residueCount: 0));
    }

    [Fact]
    public async Task UnlockedDelete_LeavesNoResidue()
    {
        string canary = WriteFile("free.dll", new byte[] { 1 });
        var residue = await ArtifactCleaner.RemoveAsync(canary, ArtifactRole.Canary, null, "c", new RecordingFileOps(), null);
        Assert.Null(residue);
        Assert.False(File.Exists(canary));
    }
}
