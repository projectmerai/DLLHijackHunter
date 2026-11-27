using DLLHijackHunter.Models;
using Spectre.Console;

namespace DLLHijackHunter.Reporting;

/// <summary>
/// F4: one console headline per Confirmed finding, printed whatever --format is. With --format json the SDK run's
/// console never named CRYPTSP.dll or NT AUTHORITY\SYSTEM: the confirmation was only in the JSON Notes.
/// </summary>
public static class ConsoleSummary
{
    /// <summary>"CONFIRMED  &lt;DLL&gt;  &lt;hole&gt;  &lt;type&gt;  as &lt;identity&gt;  (&lt;trigger&gt;)".</summary>
    public static string Headline(HijackCandidate c)
    {
        string identity = !string.IsNullOrEmpty(c.ConfirmedPrivilege) ? c.ConfirmedPrivilege! : c.RunAsAccount;
        string trigger = string.IsNullOrEmpty(c.TriggerIdentifier) ? $"{c.Trigger}" : $"{c.Trigger} {c.TriggerIdentifier}";
        return $"CONFIRMED  {c.DllName}  {c.HijackWritablePath}  {c.Type}  as {identity}  ({trigger})";
    }

    public static List<string> ConfirmedHeadlines(ScanResult result) =>
        result.Confirmed.Select(Headline).ToList();

    /// <summary>
    /// Print the headlines. Each is written as one line (not wrapped at the console width, which is 80 columns on a
    /// redirected console), through the console's writer, so the ASCII fallback still applies.
    /// </summary>
    public static void PrintConfirmed(ScanResult result, string format, string? outputPath = null)
    {
        var lines = ConfirmedHeadlines(result);
        if (lines.Count == 0) return;
        var w = AnsiConsole.Profile.Out.Writer;
        w.WriteLine();
        foreach (var l in lines) w.WriteLine(l);
        if (outputPath != null) w.WriteLine($"  (details in {outputPath})");
        else if (format is "json" or "html") w.WriteLine($"  (details in the {format} report)");
        w.Flush();
        foreach (var l in lines) ScanLogger.Audit(l);
    }
}
