using DLLHijackHunter.Discovery;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>F4: the loader ignored cmk-agent-ctl.exe.local (32-bit, no manifest, DevOverrideEnable unset) on Windows 11;
/// an unmodified real secur32.dll in .local was never loaded (f4_cause.md). No DotLocal finding there.</summary>
public sealed class T4_F4_DotLocalTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("hh-f4-").FullName;
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public void Wow64Binary_WithoutDevOverride_IsNotHonoured()
    {
        Assert.False(StaticDiscoveryEngine.DotLocalHonoured(hasManifest: false, binaryIs64Bit: false, osIs64Bit: true, devOverrideEnable: false));
    }

    [Fact]
    public void Wow64Binary_WithDevOverride_IsHonoured()
    {
        Assert.True(StaticDiscoveryEngine.DotLocalHonoured(false, false, true, devOverrideEnable: true));
    }

    [Fact]
    public void NativeBinary_KeepsTheManifestRule()
    {
        Assert.True(StaticDiscoveryEngine.DotLocalHonoured(hasManifest: false, binaryIs64Bit: true, osIs64Bit: true, devOverrideEnable: false));
        Assert.False(StaticDiscoveryEngine.DotLocalHonoured(hasManifest: true, binaryIs64Bit: true, osIs64Bit: true, devOverrideEnable: false));
        Assert.True(StaticDiscoveryEngine.DotLocalHonoured(false, binaryIs64Bit: false, osIs64Bit: false, devOverrideEnable: false));  // 32-bit OS
    }

    [Fact]
    public void ExternalManifestBesideTheExe_CountsAsAManifest()
    {
        // The comment says "embedded or external"; PEAnalyzer already reads <exe>.manifest (fixture: a temp copy of a
        // system exe with no embedded manifest is not needed: any PE + external file proves the external path).
        string exe = Path.Combine(_dir, "app.exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "where.exe"), exe);
        bool before = PEAnalyzer.Analyze(exe).HasEmbeddedManifest;
        File.WriteAllText(exe + ".manifest", "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"/>");
        Assert.True(PEAnalyzer.Analyze(exe).HasEmbeddedManifest);
        _ = before;
    }
}