using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;
using DLLHijackHunter.Scoring;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>R2: a host that crashed or failed to start after the plant, with evidence naming the
/// planted module, is Failed(host-failed-after-plant) with no penalty; otherwise Timeout stays -10.</summary>
public class T3_R2_CanaryOutcomeTests
{
    private const string Planted = @"C:\ProgramData\checkmk\agent\bin\bcrypt.dll";
    private static readonly DateTime T0 = new(2026, 11, 23, 10, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void ApplicationError_NamingThePlantedModule_IsHostFailedAfterPlant()
    {
        var ev = new HostEvidence(T0, Planted, new[]
        {
            ("Application Error", 1000, "Faulting application name: cmk-agent-ctl.exe ... Faulting module name: bcrypt.dll, version: 0.0.0.0 ... Faulting module path: C:\\ProgramData\\checkmk\\agent\\bin\\bcrypt.dll")
        });
        var (r, cause, note) = CanaryOutcome.ClassifyNoFire(ev);
        Assert.Equal(CanaryResult.Failed, r);
        Assert.Equal(CanaryOutcome.HostFailedAfterPlant, cause);
        Assert.Contains("loader reached the planted file", note);
    }

    [Fact]
    public void LoaderPopup_NamingThePlantedModule_IsHostFailedAfterPlant()
    {
        var ev = new HostEvidence(T0, Planted, new[]
        {
            ("Application Popup", 26, "Application popup: cmk-agent-ctl.exe - Entry Point Not Found : The procedure entry point X could not be located in the dynamic link library C:\\ProgramData\\checkmk\\agent\\bin\\bcrypt.dll.")
        });
        Assert.Equal(CanaryOutcome.HostFailedAfterPlant, CanaryOutcome.ClassifyNoFire(ev).cause);
    }

    [Fact]
    public void CrashOfAnotherModule_OrNoEvidence_StaysTimeout()
    {
        var other = new HostEvidence(T0, Planted, new[]
        {
            ("Application Error", 1000, "Faulting application name: x.exe ... Faulting module name: ntdll.dll ... Faulting module path: C:\\Windows\\SysWOW64\\ntdll.dll")
        });
        Assert.Equal(CanaryResult.Timeout, CanaryOutcome.ClassifyNoFire(other).result);
        Assert.Equal(CanaryResult.Timeout, CanaryOutcome.ClassifyNoFire(new HostEvidence(T0, Planted, Array.Empty<(string, int, string)>())).result);
    }

    [Fact]
    public void Scoring_HostFailedAfterPlant_HasNoPenalty_NotConfirmed_TimeoutStillMinusTen()
    {
        HijackCandidate C(CanaryResult r, string? cause) => new()
        {
            Type = HijackType.SearchOrder, Trigger = TriggerType.Service, ServiceStartType = "AUTO_START",
            RunAsAccount = "NT AUTHORITY\\SYSTEM", Confidence = 60, CanaryResult = r, CanaryFailureCause = cause,
        };
        var failed = C(CanaryResult.Failed, CanaryOutcome.HostFailedAfterPlant); new TieredScorer().Score(failed);
        var timeout = C(CanaryResult.Timeout, null); new TieredScorer().Score(timeout);
        Assert.Equal(60, failed.Confidence);
        Assert.NotEqual(ConfidenceTier.Confirmed, failed.Tier);
        Assert.Equal(50, timeout.Confidence);
    }
}
