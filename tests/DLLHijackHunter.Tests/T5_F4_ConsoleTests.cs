using System.Text.RegularExpressions;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Models;
using DLLHijackHunter.Reporting;
using Spectre.Console;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>F4: stage-ready console output. Console output is captured in memory; no file outside a temp dir.</summary>
[Collection("ServiceControl")]   // swaps the static AnsiConsole / ScanLogger seams; never run in parallel
public sealed class T5_F4_ConsoleTests : IDisposable
{
    private readonly IAnsiConsole _savedConsole = AnsiConsole.Console;
    private readonly StringWriter _out = new();
    private readonly string _dir = Directory.CreateTempSubdirectory("hh-t5f4-").FullName;

    public T5_F4_ConsoleTests()
    {
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings { Out = new AnsiConsoleOutput(_out) });
    }

    public void Dispose()
    {
        AnsiConsole.Console = _savedConsole;
        ScanLogger.Sink = null;
        ScanLogger.Initialize(null, verbose: false);
        try { Directory.Delete(_dir, true); } catch { }
    }

    private const string Bin = @"C:\Microsoft Shared\Phone Tools\CoreCon\11.0\bin";

    [Fact]
    public void ConfirmedFinding_HeadlineOnTheConsole_WithFormatJson()
    {
        var crypt = new HijackCandidate
        {
            BinaryPath = Bin + @"\IpOverUsbSvc.exe", DllName = "CRYPTSP.dll", HijackWritablePath = Bin + @"\CRYPTSP.dll",
            Type = HijackType.SearchOrder, Trigger = TriggerType.Service, TriggerIdentifier = "IpOverUsbSvc",
            RunAsAccount = "LocalSystem", CanaryResult = CanaryResult.Fired, ConfirmedPrivilege = @"NT AUTHORITY\SYSTEM",
            Tier = ConfidenceTier.Confirmed
        };
        var medium = new HijackCandidate
        {
            BinaryPath = Bin + @"\IpOverUsbEnum.exe", DllName = "ipoverusbdiscovery.dll", HijackWritablePath = Bin + @"\IpOverUsbDiscovery.dll",
            Type = HijackType.SearchOrder, Trigger = TriggerType.Service, TriggerIdentifier = "IpOverUsbSvc",
            CanaryResult = CanaryResult.Timeout, Tier = ConfidenceTier.Medium
        };
        var result = new ScanResult { Confirmed = new() { crypt }, Medium = new() { medium } };

        ConsoleSummary.PrintConfirmed(result, "json", Path.Combine(_dir, "sdk_T.json"));

        var lines = _out.ToString().Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        Assert.Contains($@"CONFIRMED  CRYPTSP.dll  {Bin}\CRYPTSP.dll  SearchOrder  as NT AUTHORITY\SYSTEM  (Service IpOverUsbSvc)", lines);
        Assert.DoesNotContain(lines, l => l.Contains("ipoverusbdiscovery.dll"));   // only Confirmed findings
    }

    [Fact]
    public void RedirectedOutput_PrintsAnAsciiArrow()
    {
        Assert.True(ConsoleText.ShouldUseAscii(outputRedirected: true, codePage: 65001));
        Assert.True(ConsoleText.ShouldUseAscii(outputRedirected: false, codePage: 437));
        Assert.False(ConsoleText.ShouldUseAscii(outputRedirected: false, codePage: 65001));
        Assert.Equal("Pipeline complete: 9 -> 7 candidates", ConsoleText.ToAscii("Pipeline complete: 9 → 7 candidates"));
        Assert.Equal("=== Phase 2 ===  + ok  ! warn  x fail  * item", ConsoleText.ToAscii("═══ Phase 2 ═══  ✓ ok  ⚠ warn  ✗ fail  • item"));
        Assert.Equal(@"C:\Users\Jürgen\a.dll", ConsoleText.ToAscii(@"C:\Users\Jürgen\a.dll"));   // other text unchanged
    }

    [Fact]
    public void FireTime_NeverPrintsANegativeAfterRunning()
    {
        var plant = new DateTime(2026, 11, 27, 7, 21, 31, 42, DateTimeKind.Utc);
        var request = plant.AddSeconds(2.0);
        var running = plant.AddSeconds(2.6);
        // The SDK run: confirm file written 2.2 s after plant, 0.4 s before the service reported RUNNING.
        string sdk = FireTime.Describe(plant, request, "start request", running, plant.AddSeconds(2.2));
        Assert.Equal("confirm file written 2.2 s after plant, 0.2 s after start request (before RUNNING)", sdk);

        for (int ms = -3000; ms <= 3000; ms += 50)
        {
            string s = FireTime.Describe(plant, request, "start request", running, running.AddMilliseconds(ms));
            Assert.DoesNotMatch(new Regex(@"-\d[\d.]* s after"), s);
            if (ms < 0) Assert.Contains("before RUNNING", s); else Assert.Contains("s after RUNNING", s);
        }
    }

    [Fact]
    public void Pid4IgnoreLines_AreNotEmittedAtVerboseLevel()
    {
        ScanLogger.Initialize(null, verbose: true);
        var lines = new List<(string level, string msg)>();
        ScanLogger.Sink = (l, m) => { lock (lines) lines.Add((l, m)); };
        var env = new EtwEnvironment
        {
            SelfPid = 100, QueryImagePath = _ => null, QueryToken = _ => null,
            FileExists = _ => false, DirectoryExists = _ => true, IsDirWritable = _ => true, Is64Bit = _ => null,
            IsSecurityProductImage = _ => false, IsToolArtifact = _ => false,
        };
        var engine = new ETWDiscoveryEngine(ScanProfile.FromName("aggressive"), env);
        engine.HandleFileIOCreate(4, Bin.ToUpperInvariant() + @"\IPOVERUSBPC.DLL");

        List<(string level, string msg)> copy; lock (lines) copy = lines.ToList();
        var ignored = copy.Where(x => x.msg.Contains("ignored open") && x.msg.Contains("PID 4")).ToList();
        Assert.NotEmpty(ignored);                                     // still in the log file
        Assert.DoesNotContain(ignored, x => x.level == "DEBUG");      // not a verbose (console) line
        Assert.DoesNotContain("ignored open", _out.ToString());       // nothing on the console
    }
}
