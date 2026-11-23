using DLLHijackHunter.Models;

namespace DLLHijackHunter.Discovery;

/// <summary>
/// Companion executables of services: EXEs a service may launch as children (e.g. a controller it
/// copies into its data directory), found read-only from the service's related directories.
/// </summary>
internal static class CompanionDiscovery
{
    internal sealed record ServiceEntry(string Name, string BinaryPath, string Account, string? ImagePath,
        IReadOnlyList<string> ParameterValues, string StartType = "AUTO_START");

    internal sealed record Companion(string ExePath, string Service, string Account, string Reason);

    internal sealed class Env
    {
        public string[] ProgramFilesRoots { get; init; } = Array.Empty<string>();
        public string ProgramData { get; init; } = "";
        public string SystemRoot { get; init; } = "";
        public Func<string, string?, bool> IsDirWritable { get; init; } = (_, _) => false;
        public Func<string, (bool guarded, string reason)> Guard { get; init; } = _ => (false, "");
    }

    // main (59bf369): no companion discovery.
    internal static IReadOnlyList<string> RelatedDirectories(ServiceEntry s, Env env) => Array.Empty<string>();

    internal static List<Companion> Find(IEnumerable<ServiceEntry> services, Env env, int maxDepth = 3,
        int maxExesPerService = 200) => new();

    internal static DiscoveryContext ToContext(Companion c, string startType) => new();
}
