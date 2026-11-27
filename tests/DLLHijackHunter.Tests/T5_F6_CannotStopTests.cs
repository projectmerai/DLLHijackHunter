using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// F6: never start a stopped service the tool cannot stop again (TIER 5 VM run: gpsvc was Stopped in the snapshot, the
/// ETW phase started it, and every later "sc stop gpsvc" failed with OpenService error 5: exit 4). A fake SCM; no real
/// service is touched.
/// </summary>
[Collection("ServiceControl")]   // mutates ServiceControl's static seams and the ScanLogger sink; never run in parallel
public sealed class T5_F6_CannotStopTests : IDisposable
{
    private readonly IScm _savedScm = ServiceControl.Scm;
    private readonly ServiceStateTracker _savedTracker = ServiceControl.Tracker;
    private readonly Func<string, (bool, string)> _savedGuard = ServiceControl.Guard;

    public T5_F6_CannotStopTests()
    {
        ServiceControl.Tracker = new ServiceStateTracker();
        ServiceControl.Guard = _ => (false, "");
        ScanStats.Reset();
    }

    public void Dispose()
    {
        ServiceControl.Scm = _savedScm; ServiceControl.Tracker = _savedTracker; ServiceControl.Guard = _savedGuard;
        ScanLogger.Sink = null;
        ScanStats.Reset();
    }

    /// <summary>
    /// A stopped service. <c>DenyStop</c>: opening it with SERVICE_START | SERVICE_STOP fails with error 5 (gpsvc).
    /// <c>AcceptsStop</c>: whether the running service's dwControlsAccepted has SERVICE_ACCEPT_STOP.
    /// </summary>
    private sealed class F6Scm : IScm
    {
        public SvcState State = SvcState.Stopped;
        public bool DenyStop, AcceptsStop = true;
        public readonly List<string> Commands = new();
        public SvcStatus Query(string name) => new(State, State == SvcState.Running ? 4242 : 0, "AUTO_START");
        public Task<(ServiceActionOutcome outcome, string output)> SendAsync(string verb, string name, int timeoutMs)
        {
            Commands.Add($"{verb}@{State}");
            if (verb == "start" && State == SvcState.Stopped) State = SvcState.Running;
            else if (verb == "stop" && State == SvcState.Running && !DenyStop && AcceptsStop) State = SvcState.Stopped;
            return Task.FromResult((ServiceActionOutcome.Sent, verb == "stop" && DenyStop ? "[SC] OpenService FAILED 5:" : "ok"));
        }
        public Task Delay(TimeSpan t) => Task.CompletedTask;
        public string? CheckStartStopAccess(string name) => DenyStop ? "OpenService(SERVICE_START | SERVICE_STOP) failed 5: access denied" : null;
        public int? ControlsAccepted(string name) => State == SvcState.Running ? (AcceptsStop ? 0x1 : 0x0) : null;
    }

    private static int CannotStopSkipped() =>
        (int?)typeof(ScanStats).GetProperty("CannotStopSkipped")?.GetValue(null) ?? -1;

    [Fact]
    public async Task StopOpenDenied_NotStarted_LoggedAtInfo_AndCounted()
    {
        var scm = new F6Scm { DenyStop = true };
        ServiceControl.Scm = scm;
        var lines = new List<(string level, string msg)>();
        ScanLogger.Sink = (l, m) => { lock (lines) lines.Add((l, m)); };

        await ServiceControl.StartAsync("T5F6Denied", 5000, "etw-trigger");

        Assert.DoesNotContain(scm.Commands, c => c.StartsWith("start@"));
        Assert.Equal(SvcState.Stopped, scm.State);
        List<(string level, string msg)> copy; lock (lines) copy = lines.ToList();
        Assert.Contains(copy, x => x.level == "INFO" &&
            x.msg.StartsWith("not starting stopped service T5F6Denied: tool cannot stop it again (") && x.msg.Contains("failed 5"));
        Assert.Equal(1, CannotStopSkipped());
        Assert.Null(await ServiceControl.RestoreAsync("T5F6Denied", "etw-trigger"));   // still Stopped = its snapshot
    }

    [Fact]
    public async Task StopOpenAllowed_StartedAsBefore()   // control: unchanged behaviour
    {
        var scm = new F6Scm();
        ServiceControl.Scm = scm;
        await ServiceControl.StartAsync("T5F6Allowed", 5000, "etw-trigger");
        Assert.Contains("start@Stopped", scm.Commands);
        Assert.Equal(SvcState.Running, scm.State);
        Assert.DoesNotContain(ScanSession.Residue, r => r.Service == "T5F6Allowed");
        Assert.Null(await ServiceControl.RestoreAsync("T5F6Allowed", "etw-trigger"));   // stopped again: snapshot state
        Assert.Equal(SvcState.Stopped, scm.State);
    }

    [Fact]
    public async Task StartedButDoesNotAcceptStop_ServiceNotRestorableResidue()
    {
        var scm = new F6Scm { AcceptsStop = false };
        ServiceControl.Scm = scm;
        await ServiceControl.StartAsync("T5F6NoStop", 5000, "etw-trigger");
        // F6 refinement: provisional until the end-of-scan check, which reports it (still Running). By reflection, so the
        // file still compiles against the base commit for the red run (there the method does not exist).
        await (typeof(ServiceControl).GetMethod("ResolveProvisionalAsync")?.Invoke(null, null) as Task ?? Task.CompletedTask);

        var r = Assert.Single(ScanSession.Residue, x => x.Service == "T5F6NoStop");
        Assert.Equal("service-not-restorable", r.Kind);
        Assert.Equal("Stopped", r.ExpectedState);
        Assert.Equal("Running", r.ActualState);
        Assert.Equal(4, Program.ComputeExitCode(0, ScanSession.Residue.Count));   // still exit 4
        // Not treated as restorable: no stop attempts, no second (service-state) residue entry.
        int stopsBefore = scm.Commands.Count(c => c.StartsWith("stop@"));
        Assert.Null(await ServiceControl.RestoreAsync("T5F6NoStop", "etw-trigger"));
        Assert.Equal(stopsBefore, scm.Commands.Count(c => c.StartsWith("stop@")));
    }
}
