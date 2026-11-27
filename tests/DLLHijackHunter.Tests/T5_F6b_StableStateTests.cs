using System.Reflection;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// F6 refinement (HijackRange EMPTY_B_r1, TIER 5 step 5): the ETW phase started edgeupdate from Stopped; 83 ms later it
/// was RUNNING with dwControlsAccepted=0x0, the scan reported service-not-restorable and exited 4, and edgeupdate then
/// stopped on its own (Stopped again before the scan ended). dwControlsAccepted is judged only at a stable state, and a
/// service that is RUNNING without SERVICE_ACCEPT_STOP is only provisionally not restorable until the end-of-scan check.
/// A fake SCM; no real service is touched. The new seams are reached by reflection so the same file runs against the
/// base commit (where they do not exist, which is the base behaviour: no end-of-scan check).
/// </summary>
[Collection("ServiceControl")]   // mutates ServiceControl's static seams and the ScanLogger sink; never run in parallel
public sealed class T5_F6b_StableStateTests : IDisposable
{
    private readonly IScm _savedScm = ServiceControl.Scm;
    private readonly ServiceStateTracker _savedTracker = ServiceControl.Tracker;
    private readonly Func<string, (bool, string)> _savedGuard = ServiceControl.Guard;

    public T5_F6b_StableStateTests()
    {
        ServiceControl.Tracker = new ServiceStateTracker();
        ServiceControl.Guard = _ => (false, "");
        ScanStats.Reset();
        SetProvisionalWaitMs(2_000);
    }

    public void Dispose()
    {
        ServiceControl.Scm = _savedScm; ServiceControl.Tracker = _savedTracker; ServiceControl.Guard = _savedGuard;
        SetProvisionalWaitMs(120_000);
        ScanLogger.Sink = null;
        ScanStats.Reset();
    }

    /// <summary>
    /// A stopped service. After a start, each status query takes the next state from <c>AfterStart</c> (the last one
    /// stays). <c>ControlsAcceptedAt</c> records the state at every dwControlsAccepted read.
    /// </summary>
    private sealed class ScriptedScm : IScm
    {
        public SvcState State = SvcState.Stopped;
        public bool AcceptsStop;
        public readonly Queue<SvcState> AfterStart = new();
        public readonly List<SvcState> ControlsAcceptedAt = new();
        public readonly List<string> Commands = new();
        private bool _started;

        public SvcStatus Query(string name)
        {
            if (_started && AfterStart.Count > 0) State = AfterStart.Dequeue();
            return new(State, State is SvcState.Running or SvcState.StartPending ? 6272 : 0, "AUTO_START");
        }
        public Task<(ServiceActionOutcome outcome, string output)> SendAsync(string verb, string name, int timeoutMs)
        {
            Commands.Add($"{verb}@{State}");
            if (verb == "start" && State == SvcState.Stopped) { _started = true; State = SvcState.StartPending; }
            else if (verb == "stop" && State == SvcState.Running && AcceptsStop) { AfterStart.Clear(); State = SvcState.Stopped; }
            return Task.FromResult((ServiceActionOutcome.Sent, "ok"));
        }
        public Task Delay(TimeSpan t) => Task.CompletedTask;
        public string? CheckStartStopAccess(string name) => null;
        public int? ControlsAccepted(string name)
        {
            ControlsAcceptedAt.Add(State);
            return State switch { SvcState.Running => AcceptsStop ? 0x1 : 0x0, SvcState.StartPending => 0x0, _ => null };
        }
    }

    private static void SetProvisionalWaitMs(int ms) =>
        typeof(ServiceControl).GetProperty("ProvisionalWaitMs", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
            ?.SetValue(null, ms);

    /// <summary>The end-of-scan check (when the residue list is built). Absent on the base commit: nothing happens.</summary>
    private static Task EndOfScanCheck() =>
        typeof(ServiceControl).GetMethod("ResolveProvisionalAsync", BindingFlags.Static | BindingFlags.Public)
            ?.Invoke(null, null) as Task ?? Task.CompletedTask;

    private static int SelfRecovered() =>
        (int?)typeof(ScanStats).GetProperty("SelfRecovered")?.GetValue(null) ?? -1;

    private static List<ResidueEntry> ResidueFor(string svc) => ScanSession.Residue.Where(r => r.Service == svc).ToList();

    [Fact]
    public async Task StartPendingWithZeroControls_ThenRunningAcceptingStop_Restorable_NoResidue()
    {
        var scm = new ScriptedScm { AcceptsStop = true };
        foreach (var s in new[] { SvcState.StartPending, SvcState.StartPending, SvcState.StartPending, SvcState.Running })
            scm.AfterStart.Enqueue(s);
        ServiceControl.Scm = scm;

        await ServiceControl.StartAsync("T5F6bPending", 5000, "etw-trigger");
        await EndOfScanCheck();

        // dwControlsAccepted was read at RUNNING (a stable state), never while START_PENDING.
        Assert.Contains(SvcState.Running, scm.ControlsAcceptedAt);
        Assert.DoesNotContain(SvcState.StartPending, scm.ControlsAcceptedAt);
        Assert.Empty(ResidueFor("T5F6bPending"));
        // Restorable as normal: stopped again, back to its snapshot state.
        Assert.Null(await ServiceControl.RestoreAsync("T5F6bPending", "etw-trigger"));
        Assert.Equal(SvcState.Stopped, scm.State);
    }

    [Fact]
    public async Task RunningWithoutStop_StoppedByTheEnd_NoResidue_Audited()
    {
        var scm = new ScriptedScm { AcceptsStop = false };
        foreach (var s in new[] { SvcState.Running, SvcState.Running, SvcState.Running, SvcState.Stopped })
            scm.AfterStart.Enqueue(s);
        ServiceControl.Scm = scm;
        var cand = new HijackCandidate();

        await ServiceControl.StartAsync("T5F6bSelfStop", 5000, "etw-trigger", cand);
        await ServiceControl.RestoreAsync("T5F6bSelfStop", "etw-trigger", cand);   // the ETW phase's restore
        await EndOfScanCheck();

        Assert.Empty(ResidueFor("T5F6bSelfStop"));
        Assert.Equal(0, Program.ComputeExitCode(0, ResidueFor("T5F6bSelfStop").Count));
        List<CanaryAction> acts; lock (cand.CanaryActions) acts = cand.CanaryActions.ToList();
        Assert.Contains(acts, a => a.Action == "service-provisionally-not-restorable" && a.Target == "T5F6bSelfStop");
        Assert.Contains(acts, a => a.Action == "service-self-recovered" &&
            a.Result.StartsWith("service-not-restorable T5F6bSelfStop returned to Stopped on its own after "));
        Assert.DoesNotContain(acts, a => a.Action == "service-not-restorable");
        Assert.Equal(1, SelfRecovered());
    }

    [Fact]
    public async Task RunningWithoutStop_StillRunningAtTheEnd_Residue_Exit4()
    {
        var scm = new ScriptedScm { AcceptsStop = false };
        scm.AfterStart.Enqueue(SvcState.Running);
        ServiceControl.Scm = scm;
        var lines = new List<(string level, string msg)>();
        ScanLogger.Sink = (l, m) => { lock (lines) lines.Add((l, m)); };

        await ServiceControl.StartAsync("T5F6bStuck", 5000, "etw-trigger");
        List<(string level, string msg)> before; lock (lines) before = lines.ToList();
        await EndOfScanCheck();

        // Provisional while the scan runs: no error yet.
        Assert.DoesNotContain(before, x => x.level == "ERROR" && x.msg.Contains("T5F6bStuck"));
        var r = Assert.Single(ResidueFor("T5F6bStuck"));
        Assert.Equal("service-not-restorable", r.Kind);
        Assert.Equal("Stopped", r.ExpectedState);
        Assert.Equal("Running", r.ActualState);
        Assert.Equal(4, Program.ComputeExitCode(0, ResidueFor("T5F6bStuck").Count));
        // No stop was attempted on a service that does not accept one.
        Assert.DoesNotContain(scm.Commands, c => c.StartsWith("stop@"));
    }
}
