using Spectre.Console;

namespace DLLHijackHunter;

/// <summary>
/// Simple logging abstraction that writes to both console (via Spectre.Console)
/// and an optional log file. Thread-safe for use with ETW and async operations.
/// </summary>
public static class ScanLogger
{
    private static StreamWriter? _fileWriter;
    private static bool _verbose;
    private static readonly object _lock = new();

    public static void Initialize(string? logFilePath, bool verbose)
    {
        _verbose = verbose;

        if (!string.IsNullOrEmpty(logFilePath))
        {
            try
            {
                _fileWriter = new StreamWriter(logFilePath, append: false) { AutoFlush = true };
                _fileWriter.WriteLine($"DLLHijackHunter Log — {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
                _fileWriter.WriteLine(new string('─', 60));
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[yellow]Warning: Could not create log file: {Markup.Escape(ex.Message)}[/]");
            }
        }
    }

    public static void Info(string message)
    {
        AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");
        WriteToFile("INFO", message);
    }

    public static void Warn(string message)
    {
        AnsiConsole.MarkupLine($"[yellow]⚠ {Markup.Escape(message)}[/]");
        WriteToFile("WARN", message);
    }

    public static void Error(string message)
    {
        AnsiConsole.MarkupLine($"[red]✗ {Markup.Escape(message)}[/]");
        WriteToFile("ERROR", message);
    }

    public static void Debug(string message)
    {
        if (_verbose)
        {
            AnsiConsole.MarkupLine($"[dim]{Markup.Escape(message)}[/]");
        }
        WriteToFile("DEBUG", message);
    }

    /// <summary>
    /// Side-effect audit line: always written to the log file at Info level (independent of
    /// --verbose), never to the console.
    /// </summary>
    public static void Audit(string message) => WriteToFile("INFO", message);

    public static void Status(string message)
    {
        AnsiConsole.MarkupLine(message);
        // Strip Spectre markup for the log file
        WriteToFile("INFO", StripMarkup(message));
    }

    /// <summary>Test hook: every line written to the log, with its level (INFO, DEBUG, ...).</summary>
    internal static Action<string, string>? Sink { get; set; }

    private static void WriteToFile(string level, string message)
    {
        Sink?.Invoke(level, message);
        if (_fileWriter == null) return;

        lock (_lock)
        {
            try
            {
                _fileWriter.WriteLine($"[{DateTime.UtcNow:HH:mm:ss.fff}] [{level}] {message}");
            }
            catch { /* swallow file write errors */ }
        }
    }

    private static string StripMarkup(string text)
    {
        // Simple markup stripper for log file output
        var result = System.Text.RegularExpressions.Regex.Replace(text, @"\[/?[^\]]*\]", "");
        return result;
    }

    public static void Dispose()
    {
        try
        {
            _fileWriter?.Flush();
            _fileWriter?.Dispose();
            _fileWriter = null;
        }
        catch { }
    }
}
