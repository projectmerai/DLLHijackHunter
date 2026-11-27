using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// F3: the canary cleanup waits for the service's process to exit before deleting. SCM reports STOPPED before the
/// process has exited and unmapped the DLL; a fake process table keeps the PID alive for a while after STOPPED, and a
/// fake file system refuses the delete while it is alive (Access denied, as in the SDK run). No real service, process
/// or file outside a temp dir is touched.
/// </summary>
[Collection("ServiceControl")]   // mutates ServiceControl's static seams; never run in parallel
public sealed class T5_F3_ProcessExitWaitTests : IDisposable
{
    private readonly IScm _savedScm = ServiceControl.Scm;
    private readonly ServiceStateTracker _savedTracker = ServiceControl.Tracker;
    private readonly Func<string, (bool, string)> _savedGuard = ServiceControl.Guard;
    private readonly string _dir = Directory.CreateTempSubdirectory("hh-t5f3-").FullName;
    private const string Svc = "IpOverUsbSvc";

    public T5_F3_ProcessExitWaitTests()
    {
        ServiceControl.Tracker = new ServiceStateTracker();
        ServiceControl.Guard = _ => (false, "");
    }

    public void Dispose()
    {
        ServiceControl.Scm = _savedScm; ServiceControl.Tracker = _savedTracker; ServiceControl.Guard = _savedGuard;
        try { Directory.Delete(_dir, true); } catch { }
    }

    /// <summary>Virtual time: advanced only by the fakes' Delay.</summary>
    private sealed class Clock { public double Seconds; public double? StoppedAt; }

    /// <summary>The service's process (PID 100) lives on for <c>exitAfter</c> s after the SCM reports STOPPED.</summary>
    private sealed class FakeTable : IProcessTable
    {
        private readonly Clock _clock; private readonly FakeScm _scm; private readonly double? _exitAfter;
        private static readonly ProcInfo Proc = new(100, 640, @"C:\Microsoft Shared\Phone Tools\CoreCon\11.0\bin\IpOverUsbSvc.exe",
            new DateTime(2026, 11, 27, 7, 0, 0, DateTimeKind.Utc));
        public FakeTable(Clock c, FakeScm scm, double? exitAfter) { _clock = c; _scm = scm; _exitAfter = exitAfter; }
        public bool Alive
        {
            get
            {
                if (_scm.State == SvcState.Running) return true;
                _clock.StoppedAt ??= _clock.Seconds;
                return _exitAfter == null || _clock.Seconds - _clock.StoppedAt < _exitAfter;
            }
        }
        public ProcInfo? Current(int pid) => pid == 100 && Alive ? Proc : null;
        public ProcInfo? Find(int pid, DateTime startUtc) => pid == 100 && startUtc == Proc.StartUtc && Alive ? Proc : null;
        public bool HoldsModule(int pid, string modulePath) => pid == 100 && Alive;
        public bool Terminate(int pid, out string error) { error = "not used"; return false; }
        public Task Delay(TimeSpan t) { _clock.Seconds += t.TotalSeconds; return Task.CompletedTask; }
    }

    /// <summary>Real temp-dir files; the delete is refused while the fake process still maps the DLL.</summary>
    private sealed class LockingFileOps : RealFileOps
    {
        private readonly FakeTable _table;
        public LockingFileOps(FakeTable t) { _table = t; }
        public override void Delete(string path)
        {
            if (_table.Alive) throw new UnauthorizedAccessException($"Access to the path '{path}' is denied.");
            base.Delete(path);
        }
        public override bool ScheduleDeleteOnReboot(string path) => true;
        public override string? FindLockHolders(string path) => _table.Alive ? "IpOverUsbSvc.exe (PID 100)" : null;
    }

    private (FakeScm scm, FakeTable table, LockingFileOps fs, string canary, HijackCandidate cand) Setup(double? exitAfter)
    {
        var scm = new FakeScm(SvcState.Running) { Pid = 100 };
        ServiceControl.Scm = scm;
        var table = new FakeTable(new Clock(), scm, exitAfter);
        string canary = Path.Combine(_dir, "CRYPTSP.dll");
        File.WriteAllBytes(canary, new byte[] { 0x4D, 0x5A, 0, 0 });
        var cand = new HijackCandidate { Trigger = TriggerType.Service, TriggerIdentifier = Svc, HijackWritablePath = canary };
        return (scm, table, new LockingFileOps(table), canary, cand);
    }

    /// <summary>The canary engine's cleanup: stop (waiting for the process), then delete with the retry fallback.</summary>
    private static async Task<ResidueEntry?> Cleanup(FakeTable table, LockingFileOps fs, string canary, HijackCandidate cand)
    {
        await ServiceStopWait.StopAndWaitForExitAsync(Svc, 5000, "c1", cand, table);
        return await ArtifactCleaner.RemoveAsync(canary, ArtifactRole.Canary, null, cand.Id, fs,
            () => ServiceControl.StopAsync(Svc, 5000, "c1", cand),
            new CleanupOptions { Attempts = 3, Backoff = _ => TimeSpan.Zero },
            (a, t, r) => Audit.Record("c1", cand, a, t, r));
    }

    [Fact]
    public async Task PidSurvivesStoppedFor2s_DeleteHappensAfterTheExit_AndTheWaitIsAudited()
    {
        var (scm, table, fs, canary, cand) = Setup(exitAfter: 2.0);
        var residue = await Cleanup(table, fs, canary, cand);

        Assert.Null(residue);
        Assert.False(File.Exists(canary));
        Assert.DoesNotContain(cand.CanaryActions, a => a.Action == "file-delete-failed");
        Assert.Contains(cand.CanaryActions, a => a.Action == "file-deleted" && a.Result == "ok");
        var wait = Assert.Single(cand.CanaryActions, a => a.Action == "process-exit-wait");
        Assert.Contains("PID 100", wait.Target);
        Assert.Contains("exited 2.0 s", wait.Result);
        // The wait comes before the delete, and only one stop was sent.
        int iWait = cand.CanaryActions.FindIndex(a => a.Action == "process-exit-wait");
        int iDel = cand.CanaryActions.FindIndex(a => a.Action == "file-deleted");
        Assert.True(iWait < iDel);
        Assert.Single(scm.Commands, c => c.StartsWith("stop@"));
    }

    [Fact]
    public async Task PidNeverExits_TheRetryAndResiduePathStillApplies()
    {
        var (_, table, fs, canary, cand) = Setup(exitAfter: null);
        var residue = await Cleanup(table, fs, canary, cand);

        var wait = Assert.Single(cand.CanaryActions, a => a.Action == "process-exit-wait");
        Assert.Contains("still running", wait.Result);
        Assert.NotNull(residue);
        Assert.Equal(canary, residue!.Path);
        Assert.Equal("IpOverUsbSvc.exe (PID 100)", residue.Holder);
        Assert.True(residue.DelayedDeleteScheduled);
        Assert.Contains(cand.CanaryActions, a => a.Action == "file-delete-failed");
    }

    /// <summary>The service's process exits at STOPPED, but a child (PID 200) still maps the canary for 1.5 s.</summary>
    private sealed class ChildHoldsTable : IProcessTable
    {
        private readonly Clock _clock; private readonly FakeScm _scm;
        private static readonly ProcInfo Svc = new(100, 640, @"C:\x\IpOverUsbSvc.exe", new DateTime(2026, 11, 27, 7, 0, 0, DateTimeKind.Utc));
        private static readonly ProcInfo Child = new(200, 100, @"C:\x\IpOverUsbEnum.exe", new DateTime(2026, 11, 27, 7, 0, 1, DateTimeKind.Utc));
        public ChildHoldsTable(Clock c, FakeScm scm) { _clock = c; _scm = scm; }
        private bool Stopped { get { if (_scm.State == SvcState.Running) return false; _clock.StoppedAt ??= _clock.Seconds; return true; } }
        public bool ChildAlive => !Stopped || _clock.Seconds - _clock.StoppedAt < 1.5;
        public ProcInfo? Current(int pid) => pid == 100 && !Stopped ? Svc : null;
        public ProcInfo? Find(int pid, DateTime startUtc) => pid == 100 && !Stopped ? Svc : null;
        public IReadOnlyList<ProcInfo> Holders(string path) => ChildAlive ? new[] { Child } : Array.Empty<ProcInfo>();
        public bool HoldsModule(int pid, string modulePath) => false;
        public bool Terminate(int pid, out string error) { error = "not used"; return false; }
        public Task Delay(TimeSpan t) { _clock.Seconds += t.TotalSeconds; return Task.CompletedTask; }
    }

    private sealed class ChildLockingFileOps : RealFileOps
    {
        private readonly ChildHoldsTable _t;
        public ChildLockingFileOps(ChildHoldsTable t) { _t = t; }
        public override void Delete(string path)
        {
            if (_t.ChildAlive) throw new UnauthorizedAccessException($"Access to the path '{path}' is denied.");
            base.Delete(path);
        }
        public override bool ScheduleDeleteOnReboot(string path) => true;
    }

    [Fact]
    public async Task ServicePidExits_ButAChildStillHoldsTheCanary_DeleteWaitsForTheRelease()
    {
        var scm = new FakeScm(SvcState.Running) { Pid = 100 };
        ServiceControl.Scm = scm;
        var table = new ChildHoldsTable(new Clock(), scm);
        var fs = new ChildLockingFileOps(table);
        string canary = Path.Combine(_dir, "CRYPTSP.dll");
        File.WriteAllBytes(canary, new byte[] { 0x4D, 0x5A, 0, 0 });
        var cand = new HijackCandidate { Trigger = TriggerType.Service, TriggerIdentifier = Svc, HijackWritablePath = canary };

        await ServiceStopWait.StopAndWaitForExitAsync(Svc, 5000, "c1", cand, table, heldFile: canary);
        var residue = await ArtifactCleaner.RemoveAsync(canary, ArtifactRole.Canary, null, cand.Id, fs,
            () => ServiceControl.StopAsync(Svc, 5000, "c1", cand),
            new CleanupOptions { Attempts = 3, Backoff = _ => TimeSpan.Zero },
            (a, t, r) => Audit.Record("c1", cand, a, t, r));

        Assert.Null(residue);
        Assert.DoesNotContain(cand.CanaryActions, a => a.Action == "file-delete-failed");
        var wait = Assert.Single(cand.CanaryActions, a => a.Action == "process-exit-wait");
        Assert.Contains("IpOverUsbEnum.exe (PID 200)", wait.Result);
        Assert.Contains("released", wait.Result);
    }

    [Fact]
    public async Task StopToAnAlreadyStoppedService_IsNotSent()
    {
        var scm = new FakeScm(SvcState.Stopped);
        ServiceControl.Scm = scm;
        var cand = new HijackCandidate { Trigger = TriggerType.Service, TriggerIdentifier = Svc };
        await ServiceControl.StopAsync(Svc, 5000, "c1", cand);
        Assert.DoesNotContain(scm.Commands, c => c.StartsWith("stop@"));
        Assert.DoesNotContain(cand.CanaryActions, a => a.Action == "service-stop");
    }
}
