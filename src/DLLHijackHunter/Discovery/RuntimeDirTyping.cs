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
    // TIER 3 (b7541d5) behaviour: static Phantom findings are never retyped.
    internal static void Apply(IEnumerable<HijackCandidate> candidates, IEnumerable<(string Binary, string DllPath)> observedLoads,
        Func<string, string, bool> isStandardDir, Func<string, bool> callsRuntimeDirApi)
    { }
}
