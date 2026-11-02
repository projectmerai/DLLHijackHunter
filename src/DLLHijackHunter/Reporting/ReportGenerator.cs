using DLLHijackHunter.Models;
using Spectre.Console;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DLLHijackHunter.Reporting;

public static class ReportGenerator
{
    public static void GenerateConsoleReport(ScanResult result)
    {
        if (!Console.IsOutputRedirected) AnsiConsole.Clear();
        BannerConstants.PrintBanner();
        AnsiConsole.WriteLine();

        // Summary table
        var summaryTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Property[/]")
            .AddColumn("[bold]Value[/]");

        // Table.AddRow(string) parses Spectre markup — escape every data value.
        summaryTable.AddRow("Hostname", Markup.Escape(result.Hostname));
        summaryTable.AddRow("OS Version", Markup.Escape(result.OSVersion));
        summaryTable.AddRow("Scan Date", result.ScanDate.ToString("yyyy-MM-dd HH:mm:ss UTC"));
        summaryTable.AddRow("Scan Mode", Markup.Escape(result.ScanMode));
        summaryTable.AddRow("Profile", Markup.Escape(result.ProfileUsed));
        summaryTable.AddRow("Duration", result.ScanDuration.ToString(@"mm\:ss"));
        summaryTable.AddRow("Total Candidates", result.TotalCandidatesDiscovered.ToString());
        summaryTable.AddRow("Eliminated (Filters)", result.EliminatedByFilters.ToString());
        summaryTable.AddRow("[green bold]Total Findings[/]", $"[green bold]{result.TotalFindings}[/]");

        AnsiConsole.Write(summaryTable);
        AnsiConsole.WriteLine();

        // Tier breakdown
        var tierChart = new BarChart()
            .Width(60)
            .Label("[bold]Findings by Tier[/]")
            .CenterLabel()
            .AddItem("CONFIRMED", result.Confirmed.Count, Color.Red)
            .AddItem("HIGH", result.High.Count, Color.Orange1)
            .AddItem("MEDIUM", result.Medium.Count, Color.Yellow)
            .AddItem("LOW", result.Low.Count, Color.Grey);
        if (result.Informational.Count > 0)
            tierChart.AddItem("INFO", result.Informational.Count, Color.DarkSlateGray1);

        AnsiConsole.Write(tierChart);
        AnsiConsole.WriteLine();

        // Detailed findings
        int rank = 0;
        foreach (var finding in result.AllFindings)
        {
            rank++;
            RenderFinding(finding, rank);
        }
    }

    private static void RenderFinding(HijackCandidate c, int rank)
    {
        Color tierColor = c.Tier switch
        {
            ConfidenceTier.Confirmed => Color.Red,
            ConfidenceTier.High => Color.Orange1,
            ConfidenceTier.Medium => Color.Yellow,
            ConfidenceTier.Low => Color.Grey,
            _ => Color.DarkSlateGray1
        };

        string tierLabel = c.Tier.ToString().ToUpper();

        var panel = new Panel(new Rows(
            new Markup($"[bold]Binary:[/]   {Markup.Escape(c.BinaryPath)}"),
            new Markup($"[bold]DLL:[/]      {Markup.Escape(c.DllName)} [dim]({c.Type})[/]"),
            new Markup($"[bold]Path:[/]     {Markup.Escape(c.HijackWritablePath)}"),
            new Markup($"[bold]Trigger:[/]  {c.Trigger} \"{Markup.Escape(c.TriggerIdentifier)}\"" +
                (c.ServiceStartType != null ? $" ({Markup.Escape(c.ServiceStartType)})" : "")),
            new Markup($"[bold]Runs As:[/]  {Markup.Escape(c.RunAsAccount)}"),
            new Markup($"[bold]Proven:[/]   " + (c.CanaryResult == CanaryResult.Fired
                ? $"[green]✓ Canary fired as {Markup.Escape(c.ConfirmedPrivilege ?? "?")}, " +
                  $"{Markup.Escape(c.ConfirmedIntegrityLevel ?? "?")} integrity[/]"
                : c.CanaryResult == CanaryResult.NotTested
                    ? "[yellow]○ Not tested[/]"
                    : $"[red]✗ {c.CanaryResult}[/]")),
            new Markup($"[bold]Survives Reboot:[/] " +
                (c.SurvivesReboot ? "[green]✓ Yes[/]" : "[dim]No[/]")),
            new Markup($"[bold]Use Cases:[/] " +
                Markup.Escape(c.UseCases.Any() ? string.Join(", ", c.UseCases) : "General")),
            new Markup($"[bold]Source:[/]   {Markup.Escape(c.DiscoverySource)}" +
                (c.LoadProbe != LoadProbeResult.NotRun ? $" | [bold]Load probe:[/] {c.LoadProbe}" : "") +
                (c.KnowledgeBaseReference != null ? $" | [bold]KB:[/] {Markup.Escape(c.KnowledgeBaseReference)}" : "")),
            c.Notes.Any()
                ? new Markup($"\n[dim]{string.Join("\n", c.Notes.Select(n => "  • " + Markup.Escape(n)))}[/]")
                : new Markup("")
        ))
        {
            Header = new PanelHeader(
                $"#{rank} [[{tierLabel}]] Score: {c.FinalScore:F1} | " +
                $"Confidence: {c.Confidence:F0}% | Impact: {c.ImpactScore:F1}",
                Justify.Left),
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(tierColor)
        };

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static async Task GenerateJsonReport(ScanResult result, string outputPath)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() }
        };

        string json = JsonSerializer.Serialize(result, options);
        await File.WriteAllTextAsync(outputPath, json);
        AnsiConsole.MarkupLine($"[green]JSON report saved to: {Markup.Escape(outputPath)}[/]");
    }

    public static async Task GenerateHtmlReport(ScanResult result, string outputPath)
    {
        string html = HtmlReportTemplate.Generate(result);
        await File.WriteAllTextAsync(outputPath, html);
        AnsiConsole.MarkupLine($"[green]HTML report saved to: {Markup.Escape(outputPath)}[/]");
    }
    public static void RenderAttackChains(List<AttackChain> chains)
    {
        if (!chains.Any()) return;

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold red]⛓️ PRIVESC ATTACK CHAINS DISCOVERED[/]").RuleStyle("red"));
        AnsiConsole.WriteLine();

        foreach (var chain in chains)
        {
            var root = new Tree(new Markup($"[bold cyan]{Markup.Escape(chain.Name)}[/]"));
            root.Style = Style.Parse("cyan");

            root.AddNode(new Markup($"[dim]{Markup.Escape(chain.Description)}[/]"));
            var pathNode = root.AddNode(new Markup("[bold yellow]Attack Path:[/]"));

            foreach (var step in chain.Steps)
            {
                string actionColor = step.Action.Contains("💥") ? "bold red" : "white";
                var stepNode = pathNode.AddNode(new Markup($"[{actionColor}]{step.StepNumber}. {Markup.Escape(step.Action)}[/]"));
                
                if (!string.IsNullOrEmpty(step.Details))
                    stepNode.AddNode(new Markup($"[dim]{Markup.Escape(step.Details)}[/]"));

                if (step.Finding != null)
                {
                    var detailsTable = new Table().Border(TableBorder.Rounded).BorderColor(Color.Grey);
                    detailsTable.AddColumn("Target");
                    detailsTable.AddColumn("Vector");
                    detailsTable.AddRow(Markup.Escape(Path.GetFileName(step.Finding.BinaryPath)),
                        step.Finding.Type.ToString());
                    stepNode.AddNode(detailsTable);
                }
            }

            AnsiConsole.Write(root);
            AnsiConsole.WriteLine();
        }
    }
}