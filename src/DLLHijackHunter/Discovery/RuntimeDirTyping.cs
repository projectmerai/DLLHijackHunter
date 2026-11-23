using DLLHijackHunter.Models;

namespace DLLHijackHunter.Discovery;

/// <summary>
/// F6: a directory added at runtime (SetDllDirectory / AddDllDirectory) is invisible to static analysis.
/// ETW can see the real copy load from it.
/// </summary>
internal static class RuntimeDirTyping
{
    internal const string ObservedNotePrefix = "Real copy observed loading from ";
    internal const string SetDllDirectoryNote =
        "Binary calls SetDllDirectory/AddDllDirectory; a real copy may exist in a runtime-added directory";

    /// <param name="observedLoads">Successful DLL image loads seen by ETW: (process image path, loaded DLL path).</param>
    /// <param name="isStandardDir">Directory is in the binary's standard search order (app dir, system dirs, Windows, PATH).</param>
    /// <param name="callsRuntimeDirApi">Binary imports SetDllDirectory or AddDllDirectory.</param>
    internal static void Apply(IEnumerable<HijackCandidate> candidates, IEnumerable<(string Binary, string DllPath)> observedLoads,
        Func<string, string, bool> isStandardDir, Func<string, bool> callsRuntimeDirApi)
    {
        var loads = observedLoads.Where(l => !string.IsNullOrEmpty(l.Binary) && !string.IsNullOrEmpty(l.DllPath)).ToList();
        foreach (var c in candidates)
        {
            if (c.Type != HijackType.Phantom || string.IsNullOrEmpty(c.BinaryPath) || !Path.IsPathRooted(c.BinaryPath)) continue;
            string? holeDir = Path.GetDirectoryName(c.HijackWritablePath);
            var seen = loads.FirstOrDefault(l =>
                string.Equals(l.Binary, c.BinaryPath, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(Path.GetFileName(l.DllPath), c.DllName, StringComparison.OrdinalIgnoreCase) &&
                Path.GetDirectoryName(l.DllPath) is string dir &&
                !string.Equals(dir, holeDir, StringComparison.OrdinalIgnoreCase) &&
                !isStandardDir(c.BinaryPath, dir));
            if (seen.DllPath != null)
            {
                string dir = Path.GetDirectoryName(seen.DllPath)!;
                c.Type = HijackType.SearchOrder;
                c.DllLegitPath = seen.DllPath;
                c.Notes.Add($"{ObservedNotePrefix}{dir} (runtime-added directory)");
                ScanLogger.Debug($"F6: {c.BinaryPath} loaded {seen.DllPath} from a runtime-added directory: Phantom -> SearchOrder");
                continue;
            }
            bool calls;
            try { calls = callsRuntimeDirApi(c.BinaryPath); } catch { calls = false; }
            if (calls && !c.Notes.Contains(SetDllDirectoryNote)) c.Notes.Add(SetDllDirectoryNote);
        }
    }

    /// <summary>The directories of a binary's standard search order: its own directory, the system
    /// directories, Windows, and the PATH this machine (and the scanner) sees.</summary>
    internal static bool IsStandardDir(string binary, string dir)
    {
        string d = dir.TrimEnd('\\');
        bool Same(string? x) => x != null && string.Equals(x.TrimEnd('\\'), d, StringComparison.OrdinalIgnoreCase);
        if (Same(Path.GetDirectoryName(binary))) return true;
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (Same(Environment.SystemDirectory) || Same(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)) ||
            Same(Path.Combine(win, "System")) || Same(win)) return true;
        var path = (SearchOrderCalculator.GetPathDirsFor(null) ?? Array.Empty<string>())
            .Concat(SearchOrderCalculator.GetPathDirsFor("NT AUTHORITY\\SYSTEM") ?? Array.Empty<string>());
        return path.Any(Same);
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _callsApi = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The binary imports SetDllDirectory or AddDllDirectory (PE import table, cached).</summary>
    internal static bool CallsRuntimeDirApi(string binary) => _callsApi.GetOrAdd(binary, b =>
    {
        try { var r = PEAnalyzer.Analyze(b); return r.AnalysisError == null && (r.CallsSetDllDirectory || r.CallsAddDllDirectory); }
        catch { return false; }
    });
}
