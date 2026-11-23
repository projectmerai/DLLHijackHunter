using DLLHijackHunter.Models;

namespace DLLHijackHunter.Discovery;

/// <summary>
/// Types a finding by where the DLL really resolves once the writable position is skipped.
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

    // main (59bf369) behaviour of the ETW FileIOCreate site: always Phantom.
    internal static Resolution Classify(string probedPath, bool? processIs64Bit,
        IEnumerable<string>? laterPathDirs = null, Env? env = null) =>
        new(HijackType.Phantom, null, "");
}
