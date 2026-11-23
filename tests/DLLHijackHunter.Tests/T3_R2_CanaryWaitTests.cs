using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>R2: a Service trigger waits (after the service is stably RUNNING) up to the configurable
/// service wait, ~90 s by default, because the service may launch the DLL's host process ~30 s
/// after it starts (Checkmk's migration step). Each fire is timed.</summary>
public class T3_R2_CanaryWaitTests
{
    [Fact]
    public void ServiceTrigger_WaitsForTheServiceWait_NotJustTheSettleWindow()
    {
        Assert.Equal(90_000, CanaryWait.ForTrigger(TriggerType.Service, settleSeconds: 20, serviceWaitSeconds: 90));
        Assert.Equal(new ScanProfile().CanaryServiceWaitSeconds * 1000,
            CanaryWait.ForTrigger(TriggerType.Service, new ScanProfile().CanarySettleSeconds, new ScanProfile().CanaryServiceWaitSeconds));
        Assert.Equal(90, new ScanProfile().CanaryServiceWaitSeconds);
    }

    [Fact]
    public void ServiceWait_NeverShortensTheSettleWindow()
    {
        Assert.Equal(120_000, CanaryWait.ForTrigger(TriggerType.Service, settleSeconds: 120, serviceWaitSeconds: 90));
    }

    [Fact]
    public void OtherTriggers_KeepTheSettleWindow()
    {
        Assert.Equal(20_000, CanaryWait.ForTrigger(TriggerType.ScheduledTask, 20, 90));
        Assert.Equal(20_000, CanaryWait.ForTrigger(TriggerType.COM, 20, 90));
    }

    [Fact]
    public void FiredText_RecordsSecondsFromTheReference()
    {
        var t0 = new DateTime(2026, 11, 23, 10, 0, 0, DateTimeKind.Utc);
        string s = CanaryWait.FiredText(t0, t0.AddSeconds(31.4), "service RUNNING");
        Assert.Contains("31.4 s", s);
        Assert.Contains("after service RUNNING", s);
    }
}
