using DLLHijackHunter.Canary;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>F1: processes a scheduled-task run started are cleaned up when the trigger is stopped.</summary>
public class T4_F1_TaskProcessTests
{
    private static readonly DateTime Run = new(2026, 11, 23, 12, 0, 0, DateTimeKind.Utc);
    private const int Scheduler = 1500;                       // svchost hosting the Schedule service
    private const string Canary = @"C:\HijackRange\TP-SEARCHORDER-PATH\pathdir\helper.dll";

    private sealed class FakeTable : IProcessTable
    {
        public readonly Dictionary<int, ProcInfo> Live = new();
        public readonly HashSet<int> Holders = new();
        public readonly List<int> Terminated = new();
        public int ExitAfterPolls = -1;                         // >= 0: every live process exits after this many polls
        private int _polls;
        public ProcInfo? Find(int pid, DateTime startUtc)
        {
            if (ExitAfterPolls >= 0 && ++_polls > ExitAfterPolls) Live.Clear();
            return Live.TryGetValue(pid, out var p) && p.StartUtc == startUtc ? p : null;
        }
        public bool HoldsModule(int pid, string modulePath) => Holders.Contains(pid);
        public bool Terminate(int pid, out string error) { Terminated.Add(pid); Live.Remove(pid); error = ""; return true; }
        public Task Delay(TimeSpan t) => Task.CompletedTask;
    }

    private static ProcInfo P(int pid, int ppid, string image, double secondsAfterRun) =>
        new(pid, ppid, image, Run.AddSeconds(secondsAfterRun));

    [Fact]
    public void Collect_RecordsOnlyProcessesStartedByTheSchedulerAfterRun()
    {
        var started = new[]
        {
            P(1316, Scheduler, @"C:\HijackRange\TP-SEARCHORDER-PATH\app\hr_task1.exe", 0.4),   // the task's process
            P(1400, 1316, @"C:\Windows\System32\conhost.exe", 0.5),                           // its child
            P(1316 + 1000, 777, @"C:\HijackRange\TP-SEARCHORDER-PATH\app\hr_task1.exe", 0.6), // same image, other parent
            P(1200, Scheduler, @"C:\Other\early.exe", -5),                                    // started before /run
        };
        var rec = TaskProcessTracker.Collect(started, Run, new HashSet<int> { Scheduler });
        Assert.Equal(new[] { 1316, 1400 }, rec.Select(r => r.Pid).OrderBy(x => x).ToArray());
    }

    [Fact]
    public async Task SurvivorHoldingTheCanary_IsTerminated_AndAudited()
    {
        var p = P(1316, Scheduler, @"C:\HijackRange\TP-SEARCHORDER-PATH\app\hr_task1.exe", 0.4);
        var table = new FakeTable(); table.Live[1316] = p; table.Holders.Add(1316);
        var c = new HijackCandidate();
        await TaskProcessTracker.CleanupAsync(c, "canary", new[] { p }, Canary, table, _ => false, waitMs: 2000);
        Assert.Equal(new[] { 1316 }, table.Terminated);
        Assert.Contains(c.CanaryActions, a => a.Action == "task-process-wait");
        Assert.Contains(c.CanaryActions, a => a.Action == "task-process-terminated" && a.Result.Contains("1316"));
    }

    [Fact]
    public async Task SurvivorNotHoldingTheCanary_IsLeftAlone()
    {
        var p = P(1316, Scheduler, @"C:\HijackRange\app\hr_task1.exe", 0.4);
        var table = new FakeTable(); table.Live[1316] = p;
        var c = new HijackCandidate();
        await TaskProcessTracker.CleanupAsync(c, "canary", new[] { p }, Canary, table, _ => false, waitMs: 2000);
        Assert.Empty(table.Terminated);
        Assert.Contains(c.CanaryActions, a => a.Action == "task-process-wait");
    }

    [Fact]
    public async Task ProcessNotStartedByTheTrigger_IsNeverTerminated()
    {
        var other = P(2222, 4, @"C:\HijackRange\app\hr_task1.exe", 0.4);   // holds the canary, but not recorded
        var table = new FakeTable(); table.Live[2222] = other; table.Holders.Add(2222);
        await TaskProcessTracker.CleanupAsync(new HijackCandidate(), "canary", Array.Empty<ProcInfo>(), Canary, table, _ => false, 2000);
        Assert.Empty(table.Terminated);
    }

    [Fact]
    public async Task GuardedOrSecurityProductImage_IsNeverTerminated()
    {
        var p = P(1316, Scheduler, @"C:\Program Files\Windows Defender\MpCmdRun.exe", 0.4);
        var table = new FakeTable(); table.Live[1316] = p; table.Holders.Add(1316);
        var c = new HijackCandidate();
        await TaskProcessTracker.CleanupAsync(c, "canary", new[] { p }, Canary, table,
            img => img.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase), 2000);
        Assert.Empty(table.Terminated);
        Assert.Contains(c.CanaryActions, a => a.Action == "task-process-terminated" && a.Result.StartsWith("refused"));
    }

    [Fact]
    public async Task ReusedPid_IsNotTheRecordedProcess_AndIsNotTerminated()
    {
        var recorded = P(1316, Scheduler, @"C:\HijackRange\app\hr_task1.exe", 0.4);
        var table = new FakeTable(); table.Live[1316] = recorded with { StartUtc = Run.AddMinutes(3) }; table.Holders.Add(1316);
        await TaskProcessTracker.CleanupAsync(new HijackCandidate(), "canary", new[] { recorded }, Canary, table, _ => false, 2000);
        Assert.Empty(table.Terminated);
    }

    [Fact]
    public async Task ProcessThatExitsWithinTheWait_IsNotTerminated()
    {
        var p = P(1316, Scheduler, @"C:\HijackRange\app\hr_task1.exe", 0.4);
        var table = new FakeTable { ExitAfterPolls = 2 }; table.Live[1316] = p; table.Holders.Add(1316);
        var c = new HijackCandidate();
        await TaskProcessTracker.CleanupAsync(c, "canary", new[] { p }, Canary, table, _ => false, 10_000);
        Assert.Empty(table.Terminated);
        Assert.Contains(c.CanaryActions, a => a.Action == "task-process-wait" && a.Result.Contains("exited"));
    }
}

/// <summary>F2: every executable companion discovery examines is logged as kept or rejected, with counts.</summary>
public sealed class T4_F2_CompanionReportTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("hh-f2-").FullName;
    private string PF86 => Path.Combine(_root, "Program Files (x86)");
    private string PD => Path.Combine(_root, "ProgramData");
    private string SvcExe => Path.Combine(PF86, @"vendor\service\svc.exe");
    private string ChildDir => Path.Combine(PD, @"vendor\agent\bin");

    public T4_F2_CompanionReportTests()
    {
        void Mz(string f) { Directory.CreateDirectory(Path.GetDirectoryName(f)!); File.WriteAllBytes(f, new byte[] { 0x4D, 0x5A, 0, 0 }); }
        Mz(SvcExe); Mz(Path.Combine(ChildDir, "child.exe")); Mz(Path.Combine(PF86, @"vendor\service\helper.exe"));
        File.WriteAllText(Path.Combine(ChildDir, "notpe.exe"), "not a PE");
    }
    public void Dispose() { try { Directory.Delete(_root, true); } catch { } }

    private CompanionDiscovery.Env Env() => new()
    {
        ProgramFilesRoots = new[] { PF86 }, ProgramData = PD, SystemRoot = Path.Combine(_root, "Windows"),
        IsDirWritable = (d, _) => d.TrimEnd('\\').Equals(ChildDir, StringComparison.OrdinalIgnoreCase),
        Guard = n => ServiceGuard.IsGuarded(new ServiceFacts(n)),
    };

    [Fact]
    public void EveryExamined_IsKeptOrRejected_WithTheReason_AndCountsMatch()
    {
        var report = new List<CompanionDiscovery.Examined>();
        var found = CompanionDiscovery.Find(new[]
        {
            new CompanionDiscovery.ServiceEntry("VendorSvc", SvcExe, "LocalSystem", $"\"{SvcExe}\"", Array.Empty<string>()),
            new CompanionDiscovery.ServiceEntry("WinDefend", SvcExe, "LocalSystem", null, Array.Empty<string>()),
        }, Env(), report: report);

        Assert.Single(found);
        var byName = report.Where(e => e.ExePath.Length > 0).ToDictionary(e => Path.GetFileName(e.ExePath), StringComparer.OrdinalIgnoreCase);
        Assert.True(byName["child.exe"].Kept);
        Assert.False(byName["helper.exe"].Kept);
        Assert.Contains("not writable", byName["helper.exe"].Reason);
        Assert.False(byName["notpe.exe"].Kept);
        Assert.Contains("not a PE", byName["notpe.exe"].Reason);
        Assert.False(byName["svc.exe"].Kept);
        Assert.Contains("service binary", byName["svc.exe"].Reason);
        Assert.Contains(report, e => e.Service == "WinDefend" && !e.Kept && e.Reason.Contains("guarded"));

        var (examined, kept, rejected) = CompanionDiscovery.Summarize(report);
        Assert.Equal(4, examined);
        Assert.Equal(1, kept);
        Assert.Equal(3, rejected);
    }

    [Fact]
    public void OverTheCap_IsRejectedWithThatReason()
    {
        for (int i = 0; i < 5; i++) File.WriteAllBytes(Path.Combine(ChildDir, $"m{i}.exe"), new byte[] { 0x4D, 0x5A });
        var report = new List<CompanionDiscovery.Examined>();
        CompanionDiscovery.Find(new[] { new CompanionDiscovery.ServiceEntry("VendorSvc", SvcExe, "LocalSystem", null, Array.Empty<string>()) },
            Env(), maxExesPerService: 3, report: report);
        Assert.Contains(report, e => !e.Kept && e.Reason.Contains("cap"));
        Assert.True(report.Count(e => e.Kept) <= 3);
    }
}

/// <summary>F3: unresolved ETW duplicates are merged into resolved twins; PID 4 (System) opens are not lookups.</summary>
public class T4_F3_EtwDuplicateTests
{
    private const string Hole = @"C:\ProgramData\checkmk\agent\bin";

    private static HijackCandidate Resolved(int? pid, string dll = "secur32.dll", string source = "etw") => new()
    {
        BinaryPath = Hole + @"\cmk-agent-ctl.exe", DllName = dll, HijackWritablePath = Path.Combine(Hole, dll),
        Type = HijackType.SearchOrder, DiscoverySource = source, ObservedPid = pid,
    };

    private static HijackCandidate Unresolved(int pid, string? image, string dll = "SECUR32.DLL", string hole = Hole) => new()
    {
        BinaryPath = "", BinaryImageName = image, DllName = dll, HijackWritablePath = Path.Combine(hole.ToUpperInvariant(), dll),
        Type = HijackType.SearchOrder, DiscoverySource = "etw", ObservedPid = pid,
        Notes = { ETWDiscoveryEngine.BinaryPathUnresolvedNote },
    };

    [Fact]
    public void Merged_ByPid()
    {
        var keep = Resolved(4242);
        var list = ETWDiscoveryEngine.MergeUnresolvedDuplicates(new List<HijackCandidate> { keep, Unresolved(4242, null) });
        Assert.Same(keep, Assert.Single(list));
        Assert.Contains(keep.Notes, n => n.Contains("duplicate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Merged_ByImageName_IntoAStaticOrCompanionFinding()
    {
        var keep = Resolved(null, source: "companion");
        var list = ETWDiscoveryEngine.MergeUnresolvedDuplicates(new List<HijackCandidate> { keep, Unresolved(5555, "cmk-agent-ctl.exe") });
        Assert.Same(keep, Assert.Single(list));
    }

    [Fact]
    public void UnrelatedUnresolved_IsKept()
    {
        var keep = Resolved(4242);
        var otherDll = Unresolved(4242, null, dll: "bcrypt.dll");                      // different DLL
        var otherDir = Unresolved(4242, null, hole: @"C:\Elsewhere");                  // different hole directory
        var noMatch = Unresolved(9999, "other.exe");                                    // no PID or image match
        var list = ETWDiscoveryEngine.MergeUnresolvedDuplicates(new List<HijackCandidate> { keep, otherDll, otherDir, noMatch });
        Assert.Equal(4, list.Count);
    }

    [Fact]
    public void SystemProcessPid4_FileOpen_IsNotALookup()
    {
        var env = new EtwEnvironment
        {
            SelfPid = 100, QueryImagePath = _ => null, QueryToken = _ => null,
            FileExists = _ => false, DirectoryExists = _ => true, IsDirWritable = _ => true, Is64Bit = _ => null,
            IsSecurityProductImage = _ => false, IsToolArtifact = _ => false,
        };
        var engine = new ETWDiscoveryEngine(ScanProfile.FromName("aggressive"), env);
        engine.HandleFileIOCreate(4, Hole + @"\SECUR32.DLL");
        Assert.Empty(engine.Candidates);
        engine.HandleFileIOCreate(4321, Hole + @"\SECUR32.DLL");       // control: an ordinary PID still counts
        Assert.Single(engine.Candidates);
    }
}

/// <summary>F5: a stopped guarded service the ETW phase leaves alone is logged at Info and counted.</summary>
[Collection("ServiceControl")]
public class T4_F5_GuardSkipTests
{
    [Fact]
    public void GuardSkip_IsInfo_AndCounted()
    {
        var lines = new List<(string level, string msg)>();
        ScanLogger.Sink = (l, m) => { lock (lines) lines.Add((l, m)); };
        try
        {
            var plan = new List<ETWDiscoveryEngine.ServiceTriggerStep>
            {
                new("DoSvc", false, false, "'DoSvc' has LaunchProtected=2 (protected service)"),
                new("WinDefend", false, false, "Microsoft security service"),       // running: not a skip
                new("Spooler", false, true, null),
            };
            int n = ETWDiscoveryEngine.ReportGuardSkips(plan, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "WinDefend" });
            Assert.Equal(1, n);
            Assert.Contains(lines, x => x.level == "INFO" && x.msg.Contains("DoSvc") && x.msg.Contains("LaunchProtected=2"));
        }
        finally { ScanLogger.Sink = null; }
    }
}

/// <summary>F6: ETW evidence of a runtime-added directory retypes a static Phantom; without it, only a note.</summary>
public class T4_F6_RuntimeDirTests
{
    private const string Bin = @"C:\HijackRange\TP-SIDELOAD-APPDIR\app\hr_svc2.exe";

    private static HijackCandidate Phantom() => new()
    {
        BinaryPath = Bin, DllName = "helper.dll", HijackWritablePath = @"C:\HijackRange\TP-SIDELOAD-APPDIR\app\helper.dll",
        Type = HijackType.Phantom, DiscoverySource = "static",
    };

    private static bool Standard(string binary, string dir) =>
        dir.Equals(Path.GetDirectoryName(binary), StringComparison.OrdinalIgnoreCase) ||
        dir.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void ObservedLoadFromNonStandardDir_UpgradesToSearchOrder()
    {
        var c = Phantom();
        RuntimeDirTyping.Apply(new[] { c }, new[] { (Bin, @"C:\HijackRange\TP-SIDELOAD-APPDIR\real\HELPER.DLL") }, Standard, _ => true);
        Assert.Equal(HijackType.SearchOrder, c.Type);
        Assert.Equal(@"C:\HijackRange\TP-SIDELOAD-APPDIR\real\HELPER.DLL", c.DllLegitPath);
        Assert.Contains(@"Real copy observed loading from C:\HijackRange\TP-SIDELOAD-APPDIR\real (runtime-added directory)", c.Notes);
    }

    [Fact]
    public void NoObservedLoad_StaysPhantom_WithTheNoteWhenTheBinaryCallsTheApi()
    {
        var c = Phantom();
        RuntimeDirTyping.Apply(new[] { c }, Array.Empty<(string, string)>(), Standard, _ => true);
        Assert.Equal(HijackType.Phantom, c.Type);
        Assert.Null(c.DllLegitPath);
        Assert.Contains(RuntimeDirTyping.SetDllDirectoryNote, c.Notes);
    }

    [Fact]
    public void LoadsThatDoNotQualify_ChangeNothing()
    {
        var c = Phantom();
        RuntimeDirTyping.Apply(new[] { c }, new[]
        {
            (Bin, @"C:\Windows\SysWOW64\helper.dll"),                                 // standard order
            (@"C:\Other\other.exe", @"C:\Somewhere\helper.dll"),                      // another binary
            (Bin, @"C:\HijackRange\TP-SIDELOAD-APPDIR\real\other.dll"),               // another DLL
        }, Standard, _ => false);
        Assert.Equal(HijackType.Phantom, c.Type);
        Assert.DoesNotContain(RuntimeDirTyping.SetDllDirectoryNote, c.Notes);
    }
}
