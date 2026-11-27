using System.Text;
using Spectre.Console;

namespace DLLHijackHunter;

/// <summary>
/// F4: ASCII fallback for the console. When the output is redirected, or the console's code page is not UTF-8, the
/// non-ASCII symbols the tool prints are written as ASCII (→ as ->, ═ as =, ✓ as +, ...). In the SDK run a redirected
/// console (OEM code page) printed "Pipeline complete: 9 → 7" as "9  7". Other text (paths, names) is unchanged.
/// </summary>
public static class ConsoleText
{
    /// <summary>The symbols the console output uses, and their ASCII forms.</summary>
    internal static readonly IReadOnlyDictionary<char, string> AsciiMap = new Dictionary<char, string>
    {
        ['→'] = "->", ['←'] = "<-", ['⇒'] = "=>", ['►'] = ">", ['▶'] = ">",
        ['═'] = "=", ['─'] = "-", ['━'] = "-", ['│'] = "|", ['║'] = "|",
        ['✓'] = "+", ['✔'] = "+", ['√'] = "+", ['✗'] = "x", ['✘'] = "x", ['×'] = "x",
        ['⚠'] = "!", ['•'] = "*", ['·'] = "*", ['—'] = "-", ['–'] = "-", ['…'] = "...",
        ['‘'] = "'", ['’'] = "'", ['“'] = "\"", ['”'] = "\"", ['≥'] = ">=", ['≤'] = "<=",
    };

    /// <summary>Use ASCII when the output is redirected or the console encoding is not UTF-8 (code page 65001).</summary>
    public static bool ShouldUseAscii(bool outputRedirected, int codePage) => outputRedirected || codePage != 65001;

    /// <summary>Whether the fallback is active for this process (set by <see cref="Install"/>).</summary>
    public static bool Ascii { get; private set; }

    /// <summary><paramref name="s"/> with the console's non-ASCII symbols replaced by their ASCII forms.</summary>
    public static string ToAscii(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        StringBuilder? sb = null;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] < 0x80 || !AsciiMap.TryGetValue(s[i], out var rep)) { sb?.Append(s[i]); continue; }
            sb ??= new StringBuilder(s.Length + 8).Append(s, 0, i);
            sb.Append(rep);
        }
        return sb?.ToString() ?? s;
    }

    /// <summary>The arrow the console uses: "→", or "->" under the ASCII fallback.</summary>
    public static string Arrow => Ascii ? "->" : "→";

    /// <summary>Route Spectre's console output through the ASCII fallback when it applies. Call once, at start-up.</summary>
    public static void Install()
    {
        int cp;
        try { cp = Console.OutputEncoding.CodePage; } catch { cp = 0; }
        Ascii = ShouldUseAscii(Console.IsOutputRedirected, cp);
        if (!Ascii) return;
        try
        {
            AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings
            {
                Out = new AsciiConsoleOutput(new AnsiConsoleOutput(Console.Out))
            });
            // Spectre's own tables, borders and charts then use their ASCII forms too.
            AnsiConsole.Profile.Capabilities.Unicode = false;
        }
        catch { /* keep the default console */ }
    }

    /// <summary>A TextWriter that writes the ASCII form of the console's symbols to an inner writer.</summary>
    internal sealed class AsciiWriter : TextWriter
    {
        private readonly TextWriter _inner;
        public AsciiWriter(TextWriter inner) { _inner = inner; }
        public override Encoding Encoding => _inner.Encoding;
        public override void Write(char value)
        {
            if (value >= 0x80 && AsciiMap.TryGetValue(value, out var rep)) _inner.Write(rep); else _inner.Write(value);
        }
        public override void Write(string? value) => _inner.Write(value == null ? null : ToAscii(value));
        public override void WriteLine(string? value) => _inner.WriteLine(value == null ? null : ToAscii(value));
        public override void Write(char[] buffer, int index, int count) => Write(new string(buffer, index, count));
        public override void Flush() => _inner.Flush();
    }

    /// <summary>Spectre console output with the ASCII writer; terminal detection and size come from the real output.</summary>
    private sealed class AsciiConsoleOutput : IAnsiConsoleOutput
    {
        private readonly IAnsiConsoleOutput _inner;
        public AsciiConsoleOutput(IAnsiConsoleOutput inner) { _inner = inner; Writer = new AsciiWriter(inner.Writer); }
        public TextWriter Writer { get; }
        public bool IsTerminal => _inner.IsTerminal;
        public int Width => _inner.Width;
        public int Height => _inner.Height;
        public void SetEncoding(Encoding encoding) => _inner.SetEncoding(encoding);
    }
}

/// <summary>
/// F4: a progress display that prints each step once. On an interactive console it is Spectre's live progress bar.
/// On a redirected / non-interactive console Spectre re-printed the bar on every refresh ("Testing candidates: 14%"
/// four times in the SDK run); there each new percentage is printed once instead.
/// </summary>
public static class ConsoleProgress
{
    public static async Task RunAsync(string title, int total, Func<Action, Task> body)
    {
        if (AnsiConsole.Profile.Capabilities.Interactive)
        {
            await AnsiConsole.Progress().StartAsync(async ctx =>
            {
                var task = ctx.AddTask($"[green]{Markup.Escape(title)}[/]", maxValue: Math.Max(1, total));
                await body(() => task.Increment(1));
            });
            return;
        }
        int done = 0, last = -1;
        await body(() =>
        {
            done++;
            int pct = total > 0 ? done * 100 / total : 100;
            if (pct == last) return;
            last = pct;
            AnsiConsole.MarkupLine($"[green]{Markup.Escape(title)}: {pct}% ({done}/{total})[/]");
        });
    }

    public static void Run(string title, int total, Action<Action> body) =>
        RunAsync(title, total, step => { body(step); return Task.CompletedTask; }).GetAwaiter().GetResult();
}
