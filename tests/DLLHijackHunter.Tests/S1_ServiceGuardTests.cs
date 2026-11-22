using DLLHijackHunter.Discovery;
using DLLHijackHunter.Safety;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>S1: no stop or restart of protected / security-product services.</summary>
public class S1_ServiceGuardTests
{
    private static string Pf(string rest) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), rest);

    private static string Pd(string rest) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), rest);

    // Pure guard: decides from name / path / LaunchProtected only, never the registry.
    private static (bool, string) PureGuard(string name) => ServiceGuard.IsGuarded(new ServiceFacts(name));

    [Fact]
    public void WinDefend_IsGuarded()
    {
        var (guarded, reason) = ServiceGuard.IsGuarded(new ServiceFacts("WinDefend"));
        Assert.True(guarded);
        Assert.False(string.IsNullOrEmpty(reason));
    }

    [Fact]
    public void LaunchProtectedService_IsGuarded()
    {
        var (guarded, reason) = ServiceGuard.IsGuarded(
            new ServiceFacts("SomeVendorSvc", @"C:\Vendor\svc.exe", null, LaunchProtected: 1));
        Assert.True(guarded);
        Assert.Contains("LaunchProtected", reason);
    }

    [Fact]
    public void ServiceBinaryUnderDefenderPath_IsGuarded()
    {
        var (guarded, _) = ServiceGuard.IsGuarded(
            new ServiceFacts("RenamedSvc", Pf(@"Windows Defender\MsMpEng.exe")));
        Assert.True(guarded);
    }

    [Fact]
    public void ServiceDllUnderDefenderPlatform_IsGuarded()
    {
        var (guarded, _) = ServiceGuard.IsGuarded(new ServiceFacts("RenamedSvc",
            @"C:\Windows\System32\svchost.exe",
            Pd(@"Microsoft\Windows Defender\Platform\4.18.25080.5-0\mpsvc.dll")));
        Assert.True(guarded);
    }

    [Fact]
    public void CSFalconService_IsGuarded_FromEmbeddedList()
    {
        var (guarded, reason) = ServiceGuard.IsGuarded(new ServiceFacts("CSFalconService"));
        Assert.True(guarded);
        Assert.Contains("CrowdStrike", reason);
    }

    [Fact]
    public void OrdinaryService_IsNotGuarded()
    {
        var (guarded, _) = ServiceGuard.IsGuarded(new ServiceFacts("HijackRangeSvc1",
            @"C:\HijackRange\TP-PHANTOM-SVC\app\hr_svc1.exe"));
        Assert.False(guarded);
    }

    [Fact]
    public void StopBuilder_RefusesGuardedName()
    {
        var saved = ServiceControl.Guard;
        try
        {
            ServiceControl.Guard = PureGuard;
            Assert.Null(ServiceControl.BuildStopArguments("WinDefend"));
            Assert.Null(ServiceControl.BuildStopArguments("windefend"));
            Assert.Equal("stop \"HijackRangeSvc1\"", ServiceControl.BuildStopArguments("HijackRangeSvc1"));
        }
        finally { ServiceControl.Guard = saved; }
    }

    [Fact]
    public void EtwRestartPlan_TargetOnDefenderFolder_ContainsNoStop()
    {
        // --target "C:\Program Files\Windows Defender": WinDefend (MsMpEng.exe) and WdNisSvc match
        // and are running, which is the situation where 9c91eab restarted them.
        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "WinDefend", "WdNisSvc" };
        var plan = ETWDiscoveryEngine.PlanServiceTriggers(new[] { "WinDefend", "WdNisSvc" },
            targetSet: true, running, PureGuard, out _);

        Assert.DoesNotContain(plan, s => s.Stop);
        Assert.All(plan, s => Assert.False(string.IsNullOrEmpty(s.Refusal)));
    }

    [Fact]
    public void EtwRestartPlan_OrdinaryTarget_StillRestarts()
    {
        var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "HijackRangeSvc1" };
        var plan = ETWDiscoveryEngine.PlanServiceTriggers(new[] { "HijackRangeSvc1" },
            targetSet: true, running, PureGuard, out _);
        var step = Assert.Single(plan);
        Assert.True(step.Stop);
        Assert.True(step.Start);
    }

    [Fact]
    public void EtwPlan_StoppedGuardedService_MayStillBeStarted()
    {
        var plan = ETWDiscoveryEngine.PlanServiceTriggers(new[] { "WinDefend" },
            targetSet: true, new HashSet<string>(), PureGuard, out _);
        var step = Assert.Single(plan);
        Assert.False(step.Stop);
        Assert.True(step.Start);
    }

    [Fact]
    public void ThirdPartyList_EveryEntryCitesAVendorSource()
    {
        var entries = ServiceGuard.ThirdPartyEntries;
        Assert.Contains(entries, e => e.Name.Equals("CSAgent", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(entries, e => e.Name.Equals("CSFalconService", StringComparison.OrdinalIgnoreCase));
        Assert.All(entries, e => Assert.StartsWith("https://", e.Source));
    }
}
