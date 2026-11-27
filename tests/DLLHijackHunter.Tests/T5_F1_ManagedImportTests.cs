using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Models;
using DLLHijackHunter.Scoring;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// Minimal 32-bit PE fixtures written into a test's own temp directory: one import (DLL!function), and optionally a
/// CLR header (data directory 14, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR), as a .NET Framework EXE has.
/// The images are never loaded or run; they are only parsed.
/// </summary>
internal static class PeFixture
{
    public static byte[] Build(string importDll, string importFunction, bool clrHeader)
    {
        var b = new byte[0x400];
        void U16(int o, int v) => BitConverter.GetBytes((ushort)v).CopyTo(b, o);
        void U32(int o, uint v) => BitConverter.GetBytes(v).CopyTo(b, o);
        void Str(int o, string s) => Encoding.ASCII.GetBytes(s + "\0").CopyTo(b, o);

        U16(0, 0x5A4D); U32(0x3C, 0x80);                                       // "MZ", e_lfanew
        U32(0x80, 0x00004550);                                                  // "PE\0\0"
        const int coff = 0x84, opt = coff + 20;
        U16(coff, 0x14C); U16(coff + 2, 1); U16(coff + 16, 0xE0); U16(coff + 18, 0x0102);   // i386, 1 section, EXE|32BIT
        U16(opt, 0x10B);                                                        // PE32
        U32(opt + 4, 0x200); U32(opt + 16, 0x1000); U32(opt + 20, 0x1000); U32(opt + 24, 0x1000);
        U32(opt + 28, 0x400000); U32(opt + 32, 0x1000); U32(opt + 36, 0x200);  // ImageBase, SectionAlign, FileAlign
        U16(opt + 40, 6); U16(opt + 48, 6);                                     // OS / subsystem version 6.0
        U32(opt + 56, 0x2000); U32(opt + 60, 0x200); U16(opt + 68, 3);          // SizeOfImage, SizeOfHeaders, console
        U32(opt + 72, 0x100000); U32(opt + 76, 0x1000); U32(opt + 80, 0x100000); U32(opt + 84, 0x1000);
        U32(opt + 92, 16);                                                      // NumberOfRvaAndSizes
        int dd = opt + 96;
        U32(dd + 1 * 8, 0x1000); U32(dd + 1 * 8 + 4, 40);                       // import directory
        U32(dd + 12 * 8, 0x1050); U32(dd + 12 * 8 + 4, 8);                      // IAT
        if (clrHeader) { U32(dd + 14 * 8, 0x10A0); U32(dd + 14 * 8 + 4, 72); }  // COM descriptor (CLR header)
        int sec = opt + 0xE0;
        Str(sec, ".text"); U32(sec + 8, 0x200); U32(sec + 12, 0x1000); U32(sec + 16, 0x200); U32(sec + 20, 0x200);
        U32(sec + 36, 0xE0000020);
        const int raw = 0x200;                                                  // RVA 0x1000 = file 0x200
        U32(raw + 0x00, 0x1040); U32(raw + 0x0C, 0x1080); U32(raw + 0x10, 0x1050);   // descriptor: ILT, Name, IAT
        U32(raw + 0x40, 0x1060); U32(raw + 0x50, 0x1060);                       // ILT / IAT -> hint/name
        Str(raw + 0x62, importFunction);
        Str(raw + 0x80, importDll);
        if (clrHeader) { U32(raw + 0xA0, 72); U16(raw + 0xA4, 2); U16(raw + 0xA6, 5); U32(raw + 0xB0, 1); }  // cb, 2.5, ILONLY
        return b;
    }
}

/// <summary>F1: a managed image's mscoree.dll gets no static search-order finding; probe/canary conflict rule.</summary>
[Collection("ServiceControl")]   // uses the static ScanLogger sink
public sealed class T5_F1_ManagedImportTests : IDisposable
{
    private readonly string _dir;

    public T5_F1_ManagedImportTests()
    {
        _dir = Directory.CreateTempSubdirectory("hh-t5f1-").FullName;
        // The fixture directory is writable by a standard user, like the SDK's install directory (only this temp dir).
        var di = new DirectoryInfo(_dir);
        var sec = di.GetAccessControl();
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        di.SetAccessControl(sec);
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private List<HijackCandidate> StaticFindings(string exe)
    {
        var ctx = new DiscoveryContext
        {
            BinaryPath = exe, TriggerType = TriggerType.Service, TriggerIdentifier = "T5FixtureSvc",
            RunAsAccount = "LocalSystem", StartType = "AUTO_START", IsAutoStart = true
        };
        var engine = new StaticDiscoveryEngine(ScanProfile.FromName("aggressive"));
        return engine.AnalyzeBinary(exe, new List<DiscoveryContext> { ctx }, PEAnalyzer.Analyze(exe));
    }

    [Fact]
    public void ManagedImage_Mscoree_NoStaticFinding_AndTheSkipIsLogged()
    {
        string exe = Path.Combine(_dir, "ManagedSvc.exe");
        File.WriteAllBytes(exe, PeFixture.Build("mscoree.dll", "_CorExeMain", clrHeader: true));
        Assert.Contains("mscoree.dll", PEAnalyzer.Analyze(exe).AllImportedDlls);

        var lines = new List<(string level, string msg)>();
        ScanLogger.Sink = (l, m) => { lock (lines) lines.Add((l, m)); };
        List<HijackCandidate> found;
        try { found = StaticFindings(exe); }
        finally { ScanLogger.Sink = null; }

        Assert.DoesNotContain(found, c => c.DllName.Equals("mscoree.dll", StringComparison.OrdinalIgnoreCase)
            && c.Type is HijackType.SearchOrder or HijackType.Phantom or HijackType.EnvPath);
        List<(string level, string msg)> copy; lock (lines) copy = lines.ToList();
        Assert.Contains(copy, x => x.level == "DEBUG" && x.msg.Contains("mscoree.dll") && x.msg.Contains(exe)
            && x.msg.Contains("CLR header"));
    }

    [Fact]
    public void NativeImage_MissingDll_FindingUnchanged()   // control: the rule is only for a managed image's mscoree
    {
        string exe = Path.Combine(_dir, "NativeSvc.exe");
        File.WriteAllBytes(exe, PeFixture.Build("hht5f1missing.dll", "Foo", clrHeader: false));
        var found = StaticFindings(exe);
        var appDir = found.Where(c => c.DllName == "hht5f1missing.dll" &&
            string.Equals(c.HijackWritablePath, Path.Combine(_dir, "hht5f1missing.dll"), StringComparison.OrdinalIgnoreCase)).ToList();
        Assert.Single(appDir);
        Assert.Equal(HijackType.Phantom, appDir[0].Type);
    }

    [Fact]
    public void NativeImage_Mscoree_StillAnalysed()   // control: without a CLR header mscoree.dll is an ordinary import
    {
        string exe = Path.Combine(_dir, "NativeMscoree.exe");
        File.WriteAllBytes(exe, PeFixture.Build("mscoree.dll", "Foo", clrHeader: false));
        var found = StaticFindings(exe);
        Assert.Contains(found, c => c.DllName == "mscoree.dll" &&
            string.Equals(c.HijackWritablePath, Path.Combine(_dir, "mscoree.dll"), StringComparison.OrdinalIgnoreCase));
    }

    private static HijackCandidate StaticCandidate(LoadProbeResult probe, CanaryResult canary) => new()
    {
        BinaryPath = @"C:\Microsoft Shared\Phone Tools\CoreCon\11.0\bin\IpOverUsbEnum.exe",
        DllName = "ipoverusbdiscovery.dll", Type = HijackType.SearchOrder,
        HijackWritablePath = @"C:\Microsoft Shared\Phone Tools\CoreCon\11.0\bin\ipoverusbdiscovery.dll",
        Trigger = TriggerType.Service, TriggerIdentifier = "IpOverUsbSvc", RunAsAccount = "LocalSystem",
        DiscoverySource = "static", Confidence = 85, LoadProbe = probe, CanaryResult = canary
    };

    [Fact]
    public void ProbeWins_CanaryTimeout_ConflictNote_AndTheProbeDoesNotRaiseTheTier()
    {
        var withProbe = StaticCandidate(LoadProbeResult.Wins, CanaryResult.Timeout);
        var withoutProbe = StaticCandidate(LoadProbeResult.NotRun, CanaryResult.Timeout);
        new TieredScorer().Score(withProbe);
        new TieredScorer().Score(withoutProbe);

        Assert.Contains("Load probe and canary disagree: probe Wins, canary Timeout", withProbe.Notes);
        Assert.Equal(withoutProbe.Tier, withProbe.Tier);
        Assert.Equal(ConfidenceTier.Medium, withProbe.Tier);   // 85 - 10 (Timeout) = 75; the probe's +10 would make it High
        Assert.Equal(withoutProbe.Confidence, withProbe.Confidence);
    }

    [Fact]
    public void ProbeWins_CanaryFired_ScoringUnchanged()   // control: no conflict, no note
    {
        var c = StaticCandidate(LoadProbeResult.Wins, CanaryResult.Fired);
        new TieredScorer().Score(c);
        Assert.Equal(ConfidenceTier.Confirmed, c.Tier);
        Assert.DoesNotContain(c.Notes, n => n.Contains("disagree"));
    }
}
