using DLLHijackHunter.Models;

namespace DLLHijackHunter.Discovery;

/// <summary>
/// Types a finding by where the DLL really resolves once the writable position is skipped.
/// If a real copy exists later in that process's search order, the writable position wins over
/// it: SearchOrder (with DllLegitPath set to that copy). Only when no copy exists anywhere in the
/// order is the DLL a true Phantom. The order checked after the writable position is the
/// system directory for the process's architecture (System32 for 64-bit processes, SysWOW64
/// for 32-bit ones), then %windir%\System, then %windir%; PATH directories are appended only
/// when the caller already models PATH (the static engine's existing EnvPath logic).
/// </summary>
internal static class HijackTypeResolver
{
    internal sealed record Resolution(HijackType Type, string? LegitPath, string Note);

    /// <summary>File-system view used by the resolver (replaceable in unit tests).</summary>
    internal sealed class Env
    {
        public Func<string, bool> FileExists { get; init; } = File.Exists;
        public string System32 { get; init; } = Environment.SystemDirectory;
        public string SysWow64 { get; init; } = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        public string Windows { get; init; } = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        public static readonly Env Default = new();
    }

    internal static IReadOnlyList<string> SystemSearchDirs(bool processIs64Bit, Env env) => new[]
    {
        processIs64Bit || string.IsNullOrEmpty(env.SysWow64) ? env.System32 : env.SysWow64,
        Path.Combine(env.Windows, "System"),
        env.Windows
    };

    /// <param name="probedPath">The writable position the loader probes (or would probe) first.</param>
    /// <param name="processIs64Bit">Bitness of the loading process; null = unknown (native assumed).</param>
    /// <param name="laterPathDirs">PATH directories after the system directories, only where the caller models PATH.</param>
    internal static Resolution Classify(string probedPath, bool? processIs64Bit,
        IEnumerable<string>? laterPathDirs = null, Env? env = null)
    {
        env ??= Env.Default;
        string dll = Path.GetFileName(probedPath);
        string? probedDir = Path.GetDirectoryName(probedPath);

        // The DLL already sits at the writable position: it can be replaced in place.
        if (env.FileExists(probedPath))
            return new Resolution(HijackType.SearchOrder, probedPath,
                $"Writable position already holds {dll}; it can be replaced in place (SearchOrder)");

        bool native = processIs64Bit ?? true;
        string bitnessNote = processIs64Bit == null ? " [process bitness unknown; native system directory assumed]" : "";
        var dirs = SystemSearchDirs(native, env).Concat(laterPathDirs ?? Enumerable.Empty<string>());
        foreach (var dir in dirs)
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            if (probedDir != null && string.Equals(dir.TrimEnd('\\'), probedDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                continue;
            string copy = Path.Combine(dir, dll);
            if (env.FileExists(copy))
                return new Resolution(HijackType.SearchOrder, copy,
                    $"Writable position probed before {copy} (SearchOrder){bitnessNote}");
        }
        return new Resolution(HijackType.Phantom, null,
            $"No copy of {dll} later in the {(native ? "64-bit" : "32-bit")} search order (Phantom){bitnessNote}");
    }
}
