using DLLHijackHunter.Discovery;
using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using DLLHijackHunter.Scoring;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>R4 C: companion executables of services (temp directory tree only).</summary>
public sealed class T3_R4C_CompanionTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("hh-r4-").FullName;
    private string PF86 => Path.Combine(_root, "Program Files (x86)");
    private string PD => Path.Combine(_root, "ProgramData");
    private string SvcExe => Path.Combine(PF86, @"vendor\service\svc.exe");
    private string ChildDir => Path.Combine(PD, @"vendor\agent\bin");
    private string ChildExe => Path.Combine(ChildDir, "child.exe");

    public T3_R4C_CompanionTests()
    {
        foreach (var f in new[] { SvcExe, ChildExe, Path.Combine(PF86, @"vendor\service\child.exe") })
        {
            Directory.CreateDirectory(Path.GetDirectoryName(f)!);
            File.WriteAllBytes(f, new byte[] { 0x4D, 0x5A });
        }
    }

    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    private CompanionDiscovery.Env Env(params string[] writableDirs)
    {
        var w = new HashSet<string>(writableDirs, StringComparer.OrdinalIgnoreCase);
        return new CompanionDiscovery.Env
        {
            ProgramFilesRoots = new[] { PF86, Path.Combine(_root, "Program Files") },
            ProgramData = PD,
            SystemRoot = Path.Combine(_root, "Windows"),
            IsDirWritable = (dir, account) => w.Contains(dir.TrimEnd('\\')),
            Guard = n => ServiceGuard.IsGuarded(new ServiceFacts(n)),
        };
    }

    private CompanionDiscovery.ServiceEntry Svc(string name = "VendorSvc", string account = "LocalSystem") =>
        new(name, SvcExe, account, $"\"{SvcExe}\"", Array.Empty<string>());

    [Fact]
    public void ChildInWritableProgramDataDir_IsFound_WithParentServiceAndAccount()
    {
        var found = CompanionDiscovery.Find(new[] { Svc() }, Env(ChildDir));
        var c = Assert.Single(found);
        Assert.Equal(ChildExe, c.ExePath, ignoreCase: true);
        Assert.Equal("VendorSvc", c.Service);
        Assert.Equal("LocalSystem", c.Account);

        var ctx = CompanionDiscovery.ToContext(c, "AUTO_START");
        Assert.Equal(TriggerType.Service, ctx.TriggerType);
        Assert.Equal("VendorSvc", ctx.TriggerIdentifier);
        Assert.Equal("NT AUTHORITY\\SYSTEM", ctx.RunAsAccount);
    }

    [Fact]
    public void ChildInNonWritableDir_IsNotReported()
    {
        Assert.Empty(CompanionDiscovery.Find(new[] { Svc() }, Env()));
    }

    [Fact]
    public void RelatedDirectories_AreInstallRootAndProgramDataVendor()
    {
        var dirs = CompanionDiscovery.RelatedDirectories(Svc(), Env());
        Assert.Contains(Path.Combine(PF86, @"vendor\service"), dirs, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(Path.Combine(PF86, "vendor"), dirs, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(Path.Combine(PD, "vendor"), dirs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(PD, dirs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(PF86, dirs, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void GuardedService_IsSkipped()
    {
        Assert.Empty(CompanionDiscovery.Find(new[] { Svc("WinDefend") }, Env(ChildDir)));
    }

    [Fact]
    public void OnlyServiceAccounts_AreConsidered()
    {
        Assert.Single(CompanionDiscovery.Find(new[] { Svc(account: "NT AUTHORITY\\LocalService") }, Env(ChildDir)));
        Assert.Single(CompanionDiscovery.Find(new[] { Svc(account: "NT AUTHORITY\\NetworkService") }, Env(ChildDir)));
        Assert.Empty(CompanionDiscovery.Find(new[] { Svc(account: @"HOST\someuser") }, Env(ChildDir)));
    }

    [Fact]
    public void Depth_AndPerServiceCap_AreEnforced()
    {
        string deep = Path.Combine(PD, @"vendor\a\b\c\d\deep.exe");   // depth 4 below ProgramData\vendor
        Directory.CreateDirectory(Path.GetDirectoryName(deep)!); File.WriteAllBytes(deep, new byte[] { 0x4D, 0x5A });
        string many = Path.Combine(PD, @"vendor\many");
        Directory.CreateDirectory(many);
        for (int i = 0; i < 250; i++) File.WriteAllBytes(Path.Combine(many, $"m{i:000}.exe"), new byte[] { 0x4D, 0x5A });

        var found = CompanionDiscovery.Find(new[] { Svc() }, Env(ChildDir, Path.GetDirectoryName(deep)!, many));
        Assert.DoesNotContain(found, c => c.ExePath.EndsWith("deep.exe", StringComparison.OrdinalIgnoreCase));
        Assert.True(found.Count <= 200);
    }

    [Fact]
    public void ServiceBinaryItself_IsNotACompanion()
    {
        var found = CompanionDiscovery.Find(new[] { Svc() }, Env(Path.GetDirectoryName(SvcExe)!, ChildDir));
        Assert.DoesNotContain(found, c => c.ExePath.Equals(SvcExe, StringComparison.OrdinalIgnoreCase));
    }

    private static HijackCandidate Companion(CanaryResult canary, bool observed = false) => new()
    {
        BinaryPath = @"C:\ProgramData\vendor\agent\bin\child.exe", DllName = "secur32.dll",
        Type = HijackType.SearchOrder, Trigger = TriggerType.Service, TriggerIdentifier = "VendorSvc",
        ServiceStartType = "AUTO_START", RunAsAccount = "NT AUTHORITY\\SYSTEM", Confidence = 95,
        DiscoverySource = "companion", CompanionOf = "VendorSvc", CompanionObserved = observed, CanaryResult = canary,
    };

    [Fact]
    public void CompanionFinding_IsCappedAtMedium_UnlessFiredOrObserved()
    {
        var c = Companion(CanaryResult.NotTested); new TieredScorer().Score(c);
        Assert.Equal(ConfidenceTier.Medium, c.Tier);
        Assert.True(c.Confidence <= 79);

        var f = Companion(CanaryResult.Fired); new TieredScorer().Score(f);
        Assert.Equal(ConfidenceTier.Confirmed, f.Tier);

        var o = Companion(CanaryResult.NotTested, observed: true); new TieredScorer().Score(o);
        Assert.Equal(ConfidenceTier.High, o.Tier);
    }
}

/// <summary>R4 B: --restart-services planning.</summary>
public class T3_R4B_RestartPlanTests
{
    private static (bool, string) Guard(string n) => ServiceGuard.IsGuarded(new ServiceFacts(n));

    [Fact]
    public void NoFlag_NoTarget_RestartsNothing()
    {
        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CheckmkService" };
        var plan = ETWDiscoveryEngine.PlanServiceTriggers(new[] { "CheckmkService" }, false, running, Guard, out _,
            new ETWDiscoveryEngine.RestartPolicy { Enabled = false, Evidence = _ => "companion finding" });
        Assert.DoesNotContain(plan, s => s.Stop);
    }

    [Fact]
    public void Flag_RestartsOnlyServicesWithEvidence_AndNeverGuarded()
    {
        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CheckmkService", "Spooler", "WinDefend" };
        var plan = ETWDiscoveryEngine.PlanServiceTriggers(new[] { "CheckmkService", "Spooler", "WinDefend" }, false, running,
            Guard, out _, new ETWDiscoveryEngine.RestartPolicy
            {
                Enabled = true,
                Evidence = n => n is "CheckmkService" or "WinDefend" ? "companion finding: C:\\ProgramData\\checkmk\\agent\\bin\\cmk-agent-ctl.exe" : null
            });
        var ck = plan.Single(s => s.Service == "CheckmkService");
        Assert.True(ck.Stop);
        Assert.Contains("companion finding", ck.Reason);
        Assert.False(plan.Single(s => s.Service == "Spooler").Stop);
        Assert.False(plan.Single(s => s.Service == "WinDefend").Stop);
    }

    [Fact]
    public void Flag_CapIsEnforced()
    {
        var names = Enumerable.Range(0, 25).Select(i => $"Svc{i:00}").ToArray();
        var running = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
        var plan = ETWDiscoveryEngine.PlanServiceTriggers(names, false, running, Guard, out bool capped,
            new ETWDiscoveryEngine.RestartPolicy { Enabled = true, Evidence = _ => "writable binary directory", Cap = 20 });
        Assert.Equal(20, plan.Count(s => s.Stop));
        Assert.True(capped);
    }

    [Fact]
    public void Target_StillRestartsUpToFive_WithoutTheFlag()
    {
        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CheckmkService" };
        var plan = ETWDiscoveryEngine.PlanServiceTriggers(new[] { "CheckmkService" }, true, running, Guard, out _);
        Assert.True(plan.Single().Stop);
    }
}
