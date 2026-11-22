using DLLHijackHunter.Canary;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Models;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// S2: only real loader activity becomes a candidate. The engine is driven through its
/// core handlers with a fake environment: no ETW session, no live process.
/// </summary>
public class S2_EtwAttributionTests
{
    private const int SelfPid = 1000;
    private const string ScannerExe = @"C:\Tools\DLLHijackHunter\DLLHijackHunter.exe";
    private const string WritableDir = @"C:\Writable";

    private static readonly string MsMpEng = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MsMpEng.exe");

    private static ETWDiscoveryEngine NewEngine(Dictionary<int, string>? livePaths = null,
        Func<string, bool>? isArtifact = null)
    {
        livePaths ??= new();
        var env = new EtwEnvironment
        {
            SelfPid = SelfPid,
            QueryImagePath = pid => livePaths.TryGetValue(pid, out var p) ? p : null,
            QueryToken = _ => ("HOST\\user", "High"),
            FileExists = _ => false,            // every probed DLL is missing
            DirectoryExists = d => d.StartsWith(WritableDir, StringComparison.OrdinalIgnoreCase),
            IsDirWritable = d => d.StartsWith(WritableDir, StringComparison.OrdinalIgnoreCase),
            Is64Bit = _ => null,
            IsToolArtifact = isArtifact ?? (p => ArtifactPaths.IsToolArtifact(p, null)),
        };
        var engine = new ETWDiscoveryEngine(ScanProfile.FromName("aggressive"), env);
        engine.SeedProcess(SelfPid, 900, ScannerExe);
        engine.LinkSeeded();
        return engine;
    }

    [Fact]
    public void Control_OrdinaryProcessLookup_CreatesCandidate()
    {
        var e = NewEngine(new() { [5000] = @"C:\App\app.exe" });
        e.HandleProcessStart(5000, 600, "app.exe", @"C:\App\app.exe");
        e.HandleFileIOCreate(5000, WritableDir + @"\missing.dll");
        var c = Assert.Single(e.Candidates);
        Assert.Equal(@"C:\App\app.exe", c.BinaryPath);
    }

    [Fact]
    public void ScannerOwnPid_CreatesNoCandidate()
    {
        var e = NewEngine();
        e.HandleFileIOCreate(SelfPid, WritableDir + @"\bfe.dll");
        Assert.Empty(e.Candidates);
    }

    [Fact]
    public void ScannerDescendants_CreateNoCandidate()
    {
        var e = NewEngine(new()
        {
            [2000] = @"C:\Windows\System32\sc.exe",
            [3000] = @"C:\Windows\System32\conhost.exe",
        });
        e.HandleProcessStart(2000, SelfPid, "sc.exe", @"C:\Windows\System32\sc.exe stop x");
        e.HandleProcessStart(3000, 2000, "conhost.exe", "");     // grandchild
        e.HandleFileIOCreate(2000, WritableDir + @"\a.dll");
        e.HandleFileIOCreate(3000, WritableDir + @"\b.dll");
        e.HandleImageLoad(2000, WritableDir + @"\c.dll");
        Assert.Empty(e.Candidates);
    }

    [Fact]
    public void SecurityProductProcess_FileOpen_CreatesNoCandidate()
    {
        var e = NewEngine();
        e.SeedProcess(2608, 700, MsMpEng);
        e.LinkSeeded();
        e.HandleFileIOCreate(2608, WritableDir + @"\helper_x.dll");
        Assert.Empty(e.Candidates);
    }

    [Fact]
    public void HhorigSidecarName_CreatesNoCandidate()
    {
        var e = NewEngine(new() { [5000] = @"C:\App\app.exe" });
        e.HandleProcessStart(5000, 600, "app.exe", "");
        e.HandleFileIOCreate(5000, WritableDir + @"\foo_hhorig.dll");
        e.HandleFileIOCreate(5000, WritableDir + @"\foo_hhorig.DLL");
        e.HandleImageLoad(5000, WritableDir + @"\foo_hhorig.dll");
        Assert.Empty(e.Candidates);
    }

    [Fact]
    public void ManifestListedPath_CreatesNoCandidate()
    {
        string dir = Directory.CreateTempSubdirectory("hh-s2-").FullName;
        try
        {
            var manifest = new ArtifactManifest(Path.Combine(dir, "artifacts.json"), requireTrustedFile: false);
            string listed = WritableDir + @"\listed.dll";
            manifest.Add(new ArtifactEntry { Path = listed, Role = ArtifactRole.Sidecar, Sha256 = "00", ScanId = "t" });

            var e = NewEngine(new() { [5000] = @"C:\App\app.exe" },
                p => ArtifactPaths.IsToolArtifact(p, manifest));
            e.HandleProcessStart(5000, 600, "app.exe", "");
            e.HandleFileIOCreate(5000, listed);
            Assert.Empty(e.Candidates);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ExitedProcess_GetsFullPathFromItsImageLoadEvent()
    {
        // OpenProcess fails (no live path): the EXE's own image-load event supplies the path.
        var e = NewEngine();
        e.HandleProcessStart(6000, 600, "hr_task1.exe", "");
        e.HandleImageLoad(6000, @"C:\HijackRange\TP-SEARCHORDER-PATH\app\hr_task1.exe");
        e.HandleFileIOCreate(6000, WritableDir + @"\helper.dll");
        var c = Assert.Single(e.Candidates);
        Assert.Equal(@"C:\HijackRange\TP-SEARCHORDER-PATH\app\hr_task1.exe", c.BinaryPath);
        Assert.Null(c.BinaryImageName);
    }

    [Fact]
    public void ExitedProcess_ImageLoadBeforeProcessStart_StillResolves()
    {
        var e = NewEngine();
        e.HandleImageLoad(6100, @"C:\App\late.exe");
        e.HandleProcessStart(6100, 600, "late.exe", "");
        e.HandleFileIOCreate(6100, WritableDir + @"\x.dll");
        Assert.Equal(@"C:\App\late.exe", Assert.Single(e.Candidates).BinaryPath);
    }

    [Fact]
    public void ExitedProcess_FullPathFromCommandLine()
    {
        var e = NewEngine();
        e.HandleProcessStart(6200, 600, "tool.exe", "\"C:\\App Dir\\tool.exe\" --run");
        e.HandleFileIOCreate(6200, WritableDir + @"\x.dll");
        Assert.Equal(@"C:\App Dir\tool.exe", Assert.Single(e.Candidates).BinaryPath);
    }

    [Fact]
    public void NoFullPath_NoteIsBinaryPathUnresolved_AndNoBareName()
    {
        var e = NewEngine();
        e.HandleProcessStart(7000, 600, "hr_task1.exe", "");
        e.HandleFileIOCreate(7000, WritableDir + @"\helper.dll");
        var c = Assert.Single(e.Candidates);
        Assert.Contains("binary path unresolved", c.Notes);
        Assert.NotEqual("hr_task1.exe", c.BinaryPath);
        Assert.True(c.BinaryPath.Length == 0 || Path.IsPathRooted(c.BinaryPath));
        Assert.Equal("hr_task1.exe", c.BinaryImageName);
    }
}
