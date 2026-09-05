using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Filters;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Scoring;
using DLLHijackHunter.Reporting;
using DLLHijackHunter.Verification;
using Spectre.Console;
using System.CommandLine;
using System.Diagnostics;
using System.Security.Principal;

namespace DLLHijackHunter;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Hidden child mode for --verify-load: resolve one DLL name with a writable directory added
        // to the search path and print where the real loader resolved it. Must run before any
        // banner/scan setup. Output is a single token on stdout consumed by the parent.
        if (args.Length >= 3 && args[0] == "--resolve-probe")
            return LoadProbe.RunChild(args[1], args[2],
                traditional: args.Length > 3 && args[3] == "traditional");

        // Prevent accidental scan freezes from the legacy console's QuickEdit Mode:
        // a stray click in the window would otherwise put it into mark/select mode and
        // block stdout, stalling a long scan until a key is pressed. Disabled for the run;
        // the original console mode is restored on exit. See Native/ConsoleQuickEdit.cs.
        var quickEditGuard = Native.ConsoleQuickEdit.Disable();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => quickEditGuard.Dispose();

        // Global exception handlers
        AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
        {
            try
            {
                AnsiConsole.MarkupLine($"[red]Fatal error: {Markup.Escape(e.ExceptionObject?.ToString() ?? "Unknown")}[/]");
            }
            catch
            {
                Console.Error.WriteLine($"Fatal error: {e.ExceptionObject}");
            }
            Environment.Exit(1);
        };

        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            e.SetObserved();
        };

        var rootCommand = new RootCommand("DLLHijackHunter — Automated DLL Hijacking Detection")
        {
            TreatUnmatchedTokensAsErrors = true
        };

        var profileOption = new Option<string>(
            aliases: new[] { "--profile", "-p" },
            description: "Scan profile: aggressive, strict, safe, redteam, uac-bypass",
            getDefaultValue: () => "aggressive");

        var outputOption = new Option<string?>(
            aliases: new[] { "--output", "-o" },
            description: "Output file path (auto-detects format from extension)");

        var formatOption = new Option<string>(
            aliases: new[] { "--format", "-f" },
            description: "Output format: console, json, html",
            getDefaultValue: () => "console");

        var minConfidenceOption = new Option<double>(
            aliases: new[] { "--min-confidence" },
            description: "Minimum confidence threshold (0-100)",
            getDefaultValue: () => 20);
        minConfidenceOption.AddValidator(result =>
        {
            var value = result.GetValueForOption(minConfidenceOption);
            if (value < 0 || value > 100)
                result.ErrorMessage = "Minimum confidence must be between 0 and 100.";
        });

        var noCanaryOption = new Option<bool>(
            aliases: new[] { "--no-canary" },
            description: "Disable canary confirmation (safe for production)");

        var noEtwOption = new Option<bool>(
            aliases: new[] { "--no-etw" },
            description: "Disable ETW runtime discovery");

        var confirmedOnlyOption = new Option<bool>(
            aliases: new[] { "--confirmed-only" },
            description: "Only show canary-confirmed findings");

        var verboseOption = new Option<bool>(
            aliases: new[] { "--verbose", "-v" },
            description: "Verbose output");

        var targetOption = new Option<string?>(
            aliases: new[] { "--target", "-t" },
            description: "Target specific binary, directory, or filename (e.g., 'notepad.exe', 'C:\\MyApp', 'C:\\MyApp\\app.exe')");

        var lpeOnlyOption = new Option<bool>(
            aliases: new[] { "--lpe-only" },
            description: "Strict LPE hunting: ignores System32/Program Files to only show Standard User vulns");

        var logFileOption = new Option<string?>(
            aliases: new[] { "--log-file" },
            description: "Write scan log to file for diagnostic purposes");

        var verifyLoadOption = new Option<bool>(
            aliases: new[] { "--verify-load" },
            description: "Verify search order with the real loader: briefly place a benign probe at " +
                "each writable position and confirm it wins the DLL search (standard user; modifies files transiently)");

        rootCommand.AddOption(profileOption);
        rootCommand.AddOption(outputOption);
        rootCommand.AddOption(formatOption);
        rootCommand.AddOption(minConfidenceOption);
        rootCommand.AddOption(noCanaryOption);
        rootCommand.AddOption(noEtwOption);
        rootCommand.AddOption(confirmedOnlyOption);
        rootCommand.AddOption(verboseOption);
        rootCommand.AddOption(targetOption);
        rootCommand.AddOption(lpeOnlyOption);
        rootCommand.AddOption(logFileOption);
        rootCommand.AddOption(verifyLoadOption);

        rootCommand.SetHandler(async (ctx) =>
        {
            var profile = ctx.ParseResult.GetValueForOption(profileOption)!;
            var output = ctx.ParseResult.GetValueForOption(outputOption);
            var format = ctx.ParseResult.GetValueForOption(formatOption)!;
            // Only treat --min-confidence as an override when the user explicitly
            // passed it; otherwise leave each profile's own threshold intact.
            var minConfResult = ctx.ParseResult.FindResultFor(minConfidenceOption);
            double? minConf = (minConfResult is null || minConfResult.IsImplicit)
                ? (double?)null
                : ctx.ParseResult.GetValueForOption(minConfidenceOption);
            var noCanary = ctx.ParseResult.GetValueForOption(noCanaryOption);
            var noEtw = ctx.ParseResult.GetValueForOption(noEtwOption);
            var confirmedOnly = ctx.ParseResult.GetValueForOption(confirmedOnlyOption);
            var verbose = ctx.ParseResult.GetValueForOption(verboseOption);
            var target = ctx.ParseResult.GetValueForOption(targetOption);
            var lpeOnly = ctx.ParseResult.GetValueForOption(lpeOnlyOption);
            var logFile = ctx.ParseResult.GetValueForOption(logFileOption);
            var verifyLoad = ctx.ParseResult.GetValueForOption(verifyLoadOption);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                AnsiConsole.MarkupLine("\n[yellow]Cancellation requested... cleaning up.[/]");
            };

            await RunScan(profile, output, format, minConf, noCanary, noEtw,
                confirmedOnly, verbose, target, lpeOnly, logFile, verifyLoad, cts.Token);
        });

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task RunScan(string profileName, string? outputPath, string format,
        double? minConfidence, bool noCanary, bool noEtw, bool confirmedOnly, bool verbose,
        string? target, bool lpeOnly, string? logFile, bool verifyLoad,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        // ─── Initialize logger ───
        ScanLogger.Initialize(logFile, verbose);

        try
        {

        // ─── Banner ───
        BannerConstants.PrintBanner();
        AnsiConsole.MarkupLine($"[dim]v2.1.0 | {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC[/]\n");

        // ─── Elevation check ───
        bool isElevated;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            isElevated = false;
        }

        if (!isElevated)
        {
            AnsiConsole.MarkupLine("[yellow]⚠ Running without elevation. " +
                "Some features (ETW, service triggers, canary) require admin.[/]");
        }

        // ─── Build profile ───
        var profile = ScanProfile.FromName(profileName);
        if (minConfidence.HasValue) profile.MinConfidence = minConfidence.Value;
        profile.Verbose = verbose;
        profile.LpeOnly = lpeOnly;
        if (verifyLoad) profile.VerifyLoad = true;
        if (noCanary) profile.RunCanary = false;
        if (noEtw) profile.RunETW = false;
        if (confirmedOnly) profile.ConfirmedOnly = true;
        if (outputPath != null) profile.OutputPath = outputPath;
        profile.OutputFormat = format;

        if (!string.IsNullOrEmpty(target))
        {
            profile.TargetPath = target;
        }

        AnsiConsole.MarkupLine($"[bold]Profile:[/] {profile.Name}");
        AnsiConsole.MarkupLine($"[bold]Mode:[/] Static" +
            (profile.RunETW ? " + ETW" : "") +
            (profile.RunCanary ? " + Canary" : ""));
        AnsiConsole.MarkupLine($"[bold]Min Confidence:[/] {profile.MinConfidence}%");
        AnsiConsole.MarkupLine($"[bold]Elevated:[/] {(isElevated ? "[green]Yes[/]" : "[yellow]No[/]")}");
        
        if (!string.IsNullOrEmpty(profile.TargetPath))
        {
            AnsiConsole.MarkupLine($"[bold]Target:[/] {Markup.Escape(profile.TargetPath)}");
        }
        
        AnsiConsole.WriteLine();

        // ═══════════════════════════════════════════════
        //  PHASE 1: DISCOVERY
        // ═══════════════════════════════════════════════
        AnsiConsole.MarkupLine("[bold cyan]═══ Phase 1: Discovery ═══[/]");

        // Static discovery
        var staticEngine = new StaticDiscoveryEngine(profile);
        var candidates = staticEngine.Discover();

        // ETW runtime discovery
        if (profile.RunETW && isElevated)
        {
            var etwEngine = new ETWDiscoveryEngine(profile);
            var etwCandidates = await etwEngine.DiscoverAsync(cancellationToken);

            // Enrich ETW candidates with static context data
            var staticContexts = staticEngine.GetLastContexts();
            etwEngine.EnrichWithStaticData(etwCandidates, staticContexts);

            // Merge ETW candidates (avoid duplicates)
            var existing = new HashSet<string>(
                candidates.Select(c => $"{c.BinaryPath}|{c.DllName}|{c.HijackWritablePath}"),
                StringComparer.OrdinalIgnoreCase);

            int newFromEtw = 0;
            foreach (var ec in etwCandidates)
            {
                string key = $"{ec.BinaryPath}|{ec.DllName}|{ec.HijackWritablePath}";
                if (existing.Add(key))
                {
                    candidates.Add(ec);
                    newFromEtw++;
                }
            }

            AnsiConsole.MarkupLine($"  [green]ETW added {newFromEtw} new candidates " +
                $"(total: {candidates.Count})[/]");
        }
        else if (profile.RunETW && !isElevated)
        {
            AnsiConsole.MarkupLine("[yellow]  Skipping ETW (requires elevation)[/]");
        }

        int totalDiscovered = candidates.Count;

        if (totalDiscovered == 0)
        {
            AnsiConsole.MarkupLine("\n[yellow]No candidates discovered.[/]");
            
            if (!string.IsNullOrEmpty(profile.TargetPath))
            {
                AnsiConsole.MarkupLine($"[yellow]No DLL hijack candidates found for target: {Markup.Escape(profile.TargetPath)}[/]");
                AnsiConsole.MarkupLine($"[dim]This could mean:[/]");
                AnsiConsole.MarkupLine($"[dim]  • The target is well-hardened (good!)[/]");
                AnsiConsole.MarkupLine($"[dim]  • The target wasn't found in execution contexts[/]");
                AnsiConsole.MarkupLine($"[dim]  • Try running with elevated privileges[/]");
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]This may indicate a very hardened system or insufficient permissions.[/]");
            }
            
            stopwatch.Stop();
            return;
        }

        // ═══════════════════════════════════════════════
        //  PHASE 2: FILTER PIPELINE
        // ═══════════════════════════════════════════════
        AnsiConsole.MarkupLine("\n[bold cyan]═══ Phase 2: Filter Pipeline ═══[/]");

        var pipeline = new FilterPipeline(profile);
        candidates = pipeline.Process(candidates);

        int afterFilters = candidates.Count;
        int eliminated = totalDiscovered - afterFilters;

        if (afterFilters == 0)
        {
            AnsiConsole.MarkupLine("\n[yellow]All candidates eliminated by filters. " +
                "No hijackable DLLs found.[/]");
            stopwatch.Stop();

            var emptyResult = new ScanResult
            {
                ScanDate = DateTime.UtcNow,
                ScanMode = "Static" + (profile.RunETW ? " + ETW" : ""),
                ProfileUsed = profile.Name,
                ScanDuration = stopwatch.Elapsed,
                TotalCandidatesDiscovered = totalDiscovered,
                EliminatedByFilters = eliminated
            };

            await GenerateOutput(emptyResult, format, outputPath);
            return;
        }

        // ═══════════════════════════════════════════════
        //  PHASE 2.5: LOAD-ORDER VERIFICATION (opt-in)
        // ═══════════════════════════════════════════════
        if (profile.VerifyLoad)
        {
            AnsiConsole.MarkupLine("\n[bold cyan]═══ Phase 2.5: Load-Order Verification ═══[/]");
            LoadProbe.VerifyAll(candidates, profile, cancellationToken);
        }

        // ═══════════════════════════════════════════════
        //  PHASE 3: CANARY CONFIRMATION
        // ═══════════════════════════════════════════════
        if (profile.RunCanary && isElevated)
        {
            AnsiConsole.MarkupLine("\n[bold cyan]═══ Phase 3: Canary Confirmation ═══[/]");

            var canaryEngine = new CanaryEngine(profile);
            candidates = await canaryEngine.ConfirmAsync(candidates, cancellationToken);
        }
        else if (profile.RunCanary && !isElevated)
        {
            AnsiConsole.MarkupLine("\n[yellow]Skipping canary confirmation (requires elevation)[/]");
            foreach (var c in candidates)
            {
                c.CanaryResult = CanaryResult.NotTested;
                c.Notes.Add("Canary not tested — requires elevation");
            }
        }

        // ═══════════════════════════════════════════════
        //  PHASE 4: SCORING & REPORTING
        // ═══════════════════════════════════════════════
        AnsiConsole.MarkupLine("\n[bold cyan]═══ Phase 4: Scoring ═══[/]");

        var scorer = new TieredScorer();
        scorer.ScoreAll(candidates);

        // Filter by minimum confidence
        candidates = candidates
            .Where(c => c.Confidence >= profile.MinConfidence)
            .OrderByDescending(c => c.FinalScore)
            .ToList();

        if (profile.ConfirmedOnly)
        {
            candidates = candidates
                .Where(c => c.CanaryResult == CanaryResult.Fired)
                .ToList();
        }

        // ═══ BUILD ATTACK CHAINS ═══
        var correlator = new AttackChainCorrelator();
        var scanResult = new ScanResult
        {
            ScanDate = DateTime.UtcNow,
            ScanMode = "Static" + (profile.RunETW ? " + ETW" : "") +
                      (profile.RunCanary ? " + Canary" : ""),
            ProfileUsed = profile.Name,
            ScanDuration = stopwatch.Elapsed,
            TotalCandidatesDiscovered = totalDiscovered,
            EliminatedByFilters = eliminated,
            SurvivedSoftGates = afterFilters,
            Confirmed = candidates.Where(c => c.Tier == ConfidenceTier.Confirmed).ToList(),
            High = candidates.Where(c => c.Tier == ConfidenceTier.High).ToList(),
            Medium = candidates.Where(c => c.Tier == ConfidenceTier.Medium).ToList(),
            Low = candidates.Where(c => c.Tier == ConfidenceTier.Low).ToList()
        };
        scanResult.AttackChains = correlator.BuildChains(scanResult.AllFindings);

        await GenerateOutput(scanResult, format, outputPath);

        AnsiConsole.MarkupLine($"\n[bold green]Scan complete in {stopwatch.Elapsed:mm\\:ss}[/]");
        AnsiConsole.MarkupLine($"[bold]Findings: {scanResult.TotalFindings}[/] " +
            $"([red]{scanResult.Confirmed.Count} confirmed[/] | " +
            $"[orange1]{scanResult.High.Count} high[/] | " +
            $"[yellow]{scanResult.Medium.Count} medium[/] | " +
            $"[grey]{scanResult.Low.Count} low[/])");
        }
        finally
        {
            ScanLogger.Dispose();
        }
    }

    private static async Task GenerateOutput(ScanResult scanResult, string format, string? outputPath)
    {
        string effectiveFormat = format;
        if (outputPath != null) effectiveFormat = Path.GetExtension(outputPath).ToLowerInvariant() switch { ".json" => "json", ".html" or ".htm" => "html", _ => format };

        if (effectiveFormat == "json") 
            await ReportGenerator.GenerateJsonReport(scanResult, outputPath ?? $"hijackhunter_{DateTime.Now:yyyyMMdd_HHmmss}.json");
        else if (effectiveFormat == "html") 
            await ReportGenerator.GenerateHtmlReport(scanResult, outputPath ?? $"hijackhunter_{DateTime.Now:yyyyMMdd_HHmmss}.html");
        else
        {
            // 1. Generate normal report
            ReportGenerator.GenerateConsoleReport(scanResult);
            
            // 2. ═══ RENDER ATTACK CHAINS ═══
            ReportGenerator.RenderAttackChains(scanResult.AttackChains);

            // 3. Save JSON backup
            if (scanResult.TotalFindings > 0) 
                await ReportGenerator.GenerateJsonReport(scanResult, $"hijackhunter_{DateTime.Now:yyyyMMdd_HHmmss}.json");
        }
    }
}