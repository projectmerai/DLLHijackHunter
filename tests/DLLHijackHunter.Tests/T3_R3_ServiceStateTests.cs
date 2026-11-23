using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// A fake SCM with pending states. A stop moves the service to STOP_PENDING and it reaches
/// STOPPED only after a few status polls. A start is rejected while the service is still
/// stopping (ERROR_SERVICE_CANNOT_ACCEPT_CTRL, 1061). A "timed out" stop returns
/// "sc.exe timed out" and stays pending for longer.
/// </summary>
internal sealed class FakeScm : IScm
{
    public SvcState State;
    public int Pid = 100;
    public int PendingPolls = 2;
    public bool NextStopTimesOut;
    public int TimedOutStopPendingPolls = 8;
    public bool StartAlwaysFails;
    public readonly List<string> Commands = new();
    private int _pendingLeft;
    private SvcState _target;

    public FakeScm(SvcState initial) { State = initial; }

    public void ForcePending(SvcState pending, SvcState target, int polls) { State = pending; _target = target; _pendingLeft = polls; }

    public SvcStatus Query(string name)
    {
        if (_pendingLeft > 0 && --_pendingLeft == 0) State = _target;
        return new SvcStatus(State, State == SvcState.Running ? Pid : 0, "AUTO_START");
    }

    public Task<(ServiceActionOutcome outcome, string output)> SendAsync(string verb, string name, int timeoutMs)
    {
        Commands.Add($"{verb}@{State}");
        if (verb == "stop")
        {
            if (State == SvcState.Stopped) return R(ServiceActionOutcome.Sent, "FAILED 1062: not started");
            if (State != SvcState.Running) return R(ServiceActionOutcome.Sent, "FAILED 1061: cannot accept control");
            bool timeout = NextStopTimesOut; NextStopTimesOut = false;
            ForcePending(SvcState.StopPending, SvcState.Stopped, timeout ? TimedOutStopPendingPolls : PendingPolls);
            return timeout ? R(ServiceActionOutcome.Failed, "sc.exe timed out") : R(ServiceActionOutcome.Sent, "STOP_PENDING");
        }
        if (StartAlwaysFails) return R(ServiceActionOutcome.Sent, "FAILED 1053: did not respond");
        if (State == SvcState.Running) return R(ServiceActionOutcome.Sent, "FAILED 1056: already running");
        if (State != SvcState.Stopped) return R(ServiceActionOutcome.Sent, "FAILED 1061: cannot accept control");
        Pid++;
        ForcePending(SvcState.StartPending, SvcState.Running, PendingPolls);
        return R(ServiceActionOutcome.Sent, "START_PENDING");
    }

    public Task Delay(TimeSpan t) => Task.CompletedTask;

    private static Task<(ServiceActionOutcome, string)> R(ServiceActionOutcome o, string s) => Task.FromResult((o, s));
}

/// <summary>R3: service state is snapshotted once, every command waits for a stable state, and the
/// snapshot state is restored and verified (or reported).</summary>
[Collection("ServiceControl")]   // mutates ServiceControl's static seams; never run in parallel
public sealed class T3_R3_ServiceStateTests : IDisposable
{
    private readonly IScm _savedScm = ServiceControl.Scm;
    private readonly ServiceStateTracker _savedTracker = ServiceControl.Tracker;
    private readonly Func<string, (bool, string)> _savedGuard = ServiceControl.Guard;

    public T3_R3_ServiceStateTests()
    {
        ServiceControl.Tracker = new ServiceStateTracker();
        ServiceControl.Guard = n => ServiceGuard.IsGuarded(new ServiceFacts(n));
    }

    public void Dispose()
    {
        ServiceControl.Scm = _savedScm; ServiceControl.Tracker = _savedTracker; ServiceControl.Guard = _savedGuard;
    }

    private const string Svc = "CheckmkService";

    /// <summary>The canary's service choreography for one candidate, as CanaryEngine runs it.</summary>
    private static async Task<ResidueEntry?> OneCandidate(FakeScm fake, bool finallyStopTimesOut, HijackCandidate c)
    {
        bool wasRunning = ServiceControl.WasRunningAtSnapshot(Svc);
        if (wasRunning) await ServiceControl.StopAsync(Svc, 5000, "canary", c);    // pre-deploy stop
        await ServiceControl.StopAsync(Svc, 10000, "canary", c);                    // TriggerService: stop ...
        await ServiceControl.StartAsync(Svc, 20000, "canary", c);                   // ... start
        fake.NextStopTimesOut = finallyStopTimesOut;
        await ServiceControl.StopAsync(Svc, 5000, "canary", c);                     // finally: stop
        return await ServiceControl.RestoreAsync(Svc, "canary", c);                 // R3: restore + verify
    }

    [Fact]
    public async Task P23Sequence_TimedOutStop_ThenStartPendingCheck_EndsRunning()
    {
        var fake = new FakeScm(SvcState.Running); ServiceControl.Scm = fake;
        await ServiceControl.EnsureSnapshotAsync(Svc);

        // Candidate 1 (SSPICLI in ck23_T): its cleanup stop times out.
        var c1 = new HijackCandidate();
        Assert.Null(await OneCandidate(fake, finallyStopTimesOut: true, c1));

        // Candidate 2 begins while the service is still START_PENDING. The decision must come from
        // the snapshot (Running), not from a live query.
        fake.ForcePending(SvcState.StartPending, SvcState.Running, 3);
        Assert.True(ServiceControl.WasRunningAtSnapshot(Svc));
        var c2 = new HijackCandidate();
        Assert.Null(await OneCandidate(fake, finallyStopTimesOut: false, c2));

        Assert.Empty(await ServiceControl.RestoreAllAsync("canary-phase"));
        Assert.Equal(SvcState.Running, fake.Query(Svc).State);
    }

    [Fact]
    public async Task EveryStopAndStart_ReturnsOnlyAtAStableState()
    {
        var fake = new FakeScm(SvcState.Running); ServiceControl.Scm = fake;
        await ServiceControl.EnsureSnapshotAsync(Svc);
        await ServiceControl.StopAsync(Svc, 5000, "t");
        Assert.Equal(SvcState.Stopped, fake.State);
        await ServiceControl.StartAsync(Svc, 5000, "t");
        Assert.Equal(SvcState.Running, fake.State);
    }

    [Fact]
    public async Task StoppedService_StaysStopped()
    {
        var fake = new FakeScm(SvcState.Stopped); ServiceControl.Scm = fake;
        await ServiceControl.EnsureSnapshotAsync(Svc);
        Assert.False(ServiceControl.WasRunningAtSnapshot(Svc));
        Assert.Null(await OneCandidate(fake, finallyStopTimesOut: true, new HijackCandidate()));
        Assert.Empty(await ServiceControl.RestoreAllAsync("t"));
        Assert.Equal(SvcState.Stopped, fake.Query(Svc).State);
    }

    [Fact]
    public async Task ServiceThatCannotBeRestored_IsServiceStateResidue_AndExitCode4()
    {
        var fake = new FakeScm(SvcState.Running); ServiceControl.Scm = fake;
        await ServiceControl.EnsureSnapshotAsync(Svc);
        var c = new HijackCandidate();
        await ServiceControl.StopAsync(Svc, 5000, "canary", c);
        fake.StartAlwaysFails = true;

        var r = await ServiceControl.RestoreAsync(Svc, "canary", c);

        Assert.NotNull(r);
        Assert.Equal("service-state", r!.Kind);
        Assert.Equal(Svc, r.Service);
        Assert.Equal("Running", r.ExpectedState);
        Assert.Equal("Stopped", r.ActualState);
        Assert.False(string.IsNullOrEmpty(r.LastError));
        Assert.True(c.CanaryActions.Count(a => a.Action == "service-restore") >= 3);   // one audit line per attempt
        Assert.Equal(4, Program.ComputeExitCode(0, residueCount: 1));
    }

    [Fact]
    public async Task SnapshotIsTakenOnce()
    {
        var fake = new FakeScm(SvcState.Running); ServiceControl.Scm = fake;
        await ServiceControl.EnsureSnapshotAsync(Svc);
        await ServiceControl.StopAsync(Svc, 5000, "t");
        await ServiceControl.EnsureSnapshotAsync(Svc);          // later call must not overwrite it
        Assert.Equal(SvcState.Running, ServiceControl.Tracker.Snapshot(Svc)!.State);
    }

    [Fact]
    public void Guard_CannotBeBypassed_ByTheNewStatePath()
    {
        Assert.Null(ServiceControl.BuildStopArguments("WinDefend"));
    }
}
