using DLLHijackHunter.Native;
using DLLHijackHunter.Safety;

namespace DLLHijackHunter.Discovery;

/// <summary>
/// Every machine query the ETW event handlers make. Production uses the defaults; unit tests
/// replace them so attribution decisions can be checked without a trace or a live process.
/// </summary>
internal sealed class EtwEnvironment
{
    /// <summary>The scanner's own PID (its descendants are tracked from ProcessStart parent PIDs).</summary>
    public int SelfPid { get; init; } = Environment.ProcessId;

    /// <summary>Full image path of a live process, or null (exited / access denied).</summary>
    public Func<int, string?> QueryImagePath { get; init; } = ETWDiscoveryEngine.TryGetFullImagePath;

    public Func<int, (string user, string integrity)?> QueryToken { get; init; } = ETWDiscoveryEngine.QueryProcessToken;

    public Func<string, bool> FileExists { get; init; } = File.Exists;
    public Func<string, bool> DirectoryExists { get; init; } = Directory.Exists;
    public Func<string, bool> IsDirWritable { get; init; } = d => AclChecker.IsDirectoryWritableByStandardUser(d);

    /// <summary>Bitness of a binary; null = let the engine read the PE header itself.</summary>
    public Func<string, bool?>? Is64Bit { get; init; }

    /// <summary>Image path belongs to a security product (S1 path list).</summary>
    public Func<string, bool> IsSecurityProductImage { get; init; } = ServiceGuard.IsSecurityProductImage;

    /// <summary>Path is a DLLHijackHunter artifact (sidecar, backup, tool folder, manifest entry).</summary>
    public Func<string, bool> IsToolArtifact { get; init; } = _ => false;
}
