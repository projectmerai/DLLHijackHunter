using DLLHijackHunter.Discovery;
using DLLHijackHunter.Models;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>R1: a finding is typed by where the DLL really resolves for that process's architecture.</summary>
public class T3_R1_TypeResolverTests
{
    private static HijackTypeResolver.Env Env(params string[] existing)
    {
        var set = new HashSet<string>(existing, StringComparer.OrdinalIgnoreCase);
        return new HijackTypeResolver.Env
        {
            FileExists = set.Contains,
            System32 = @"C:\Windows\System32",
            SysWow64 = @"C:\Windows\SysWOW64",
            Windows = @"C:\Windows",
        };
    }

    private const string Probed = @"C:\ProgramData\vendor\agent\bin\secur32.dll";

    [Fact]
    public void X86Binary_CopyInSysWow64_IsSearchOrder()
    {
        var r = HijackTypeResolver.Classify(Probed, processIs64Bit: false, null,
            Env(@"C:\Windows\SysWOW64\secur32.dll"));
        Assert.Equal(HijackType.SearchOrder, r.Type);
        Assert.Equal(@"C:\Windows\SysWOW64\secur32.dll", r.LegitPath);
        Assert.Contains(@"probed before C:\Windows\SysWOW64\secur32.dll", r.Note);
    }

    [Fact]
    public void X86Binary_CopyOnlyInSystem32_IsPhantom()
    {
        // A 32-bit process never loads the 64-bit System32 copy.
        var r = HijackTypeResolver.Classify(Probed, false, null, Env(@"C:\Windows\System32\secur32.dll"));
        Assert.Equal(HijackType.Phantom, r.Type);
        Assert.Null(r.LegitPath);
    }

    [Fact]
    public void X64Binary_CopyInSystem32_IsSearchOrder()
    {
        var r = HijackTypeResolver.Classify(Probed, true, null, Env(@"C:\Windows\System32\secur32.dll"));
        Assert.Equal(HijackType.SearchOrder, r.Type);
        Assert.Equal(@"C:\Windows\System32\secur32.dll", r.LegitPath);
    }

    [Fact]
    public void CopyInWindowsSystemOrWindowsDir_IsSearchOrder()
    {
        Assert.Equal(HijackType.SearchOrder,
            HijackTypeResolver.Classify(Probed, true, null, Env(@"C:\Windows\System\secur32.dll")).Type);
        Assert.Equal(HijackType.SearchOrder,
            HijackTypeResolver.Classify(Probed, false, null, Env(@"C:\Windows\secur32.dll")).Type);
    }

    [Fact]
    public void NoCopyAnywhere_IsPhantom()
    {
        var r = HijackTypeResolver.Classify(Probed, true, null, Env());
        Assert.Equal(HijackType.Phantom, r.Type);
        Assert.Null(r.LegitPath);
        Assert.Contains("Phantom", r.Note);
    }

    [Fact]
    public void LaterPathDirectory_CountsOnlyWhenTheCallerModelsPath()
    {
        var env = Env(@"C:\Tools\secur32.dll");
        Assert.Equal(HijackType.Phantom, HijackTypeResolver.Classify(Probed, true, null, env).Type);
        Assert.Equal(HijackType.SearchOrder,
            HijackTypeResolver.Classify(Probed, true, new[] { @"C:\Tools" }, env).Type);
    }

    [Fact]
    public void DllAlreadyAtWritablePosition_IsSearchOrderOverwrite()
    {
        var r = HijackTypeResolver.Classify(Probed, true, null, Env(Probed));
        Assert.Equal(HijackType.SearchOrder, r.Type);
        Assert.Equal(Probed, r.LegitPath);
    }

    [Fact]
    public void EnvPath_IsUnchanged_StaticPathDirectoryRuleWins()
    {
        // The static engine's existing EnvPath rule (hijack position in a PATH directory that is
        // not the binary's own directory) still decides EnvPath, whatever the resolver says.
        var r = HijackTypeResolver.Classify(@"C:\PathDir\helper.dll", true, new[] { @"C:\RealDir" },
            Env(@"C:\RealDir\helper.dll"));
        Assert.Equal(HijackType.EnvPath, StaticDiscoveryEngine.TypeForStaticPosition(isPathDirHijack: true, r));
        Assert.Equal(HijackType.EnvPath, StaticDiscoveryEngine.TypeForStaticPosition(true,
            HijackTypeResolver.Classify(@"C:\PathDir\helper.dll", true, null, Env())));
        Assert.Equal(r.Type, StaticDiscoveryEngine.TypeForStaticPosition(false, r));
    }
}
