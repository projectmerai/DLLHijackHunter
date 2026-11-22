namespace DLLHijackHunter.Models;

/// <summary>
/// Unified execution context representing a binary discovered via static enumeration
/// or ETW runtime tracing. Combines fields from both discovery sources.
/// </summary>
public class DiscoveryContext
{
    // ─── Static Discovery Fields ───
    public string BinaryPath { get; set; } = "";
    // Explicit default: enum value 0 is TriggerType.Service, which made every ETW-built context
    // look like a nameless service. All static enumerators set this explicitly.
    public TriggerType TriggerType { get; set; } = TriggerType.Unknown;
    public string TriggerIdentifier { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string RunAsAccount { get; set; } = "";
    public string StartType { get; set; } = "";
    public bool IsAutoStart { get; set; }
    public bool IsSvchostService { get; set; }
    public TimeSpan? RepeatInterval { get; set; }

    // ─── ETW Runtime Fields ───
    public int Pid { get; set; }
    // Creating (parent) process as reported by ETW / NtQueryInformationProcess. 0 / "" when unknown.
    public int ParentPid { get; set; }
    public string ParentBinaryPath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    // Short image name from the kernel ProcessStart event ("app.exe").
    public string ImageName { get; set; } = "";
    // No full image path could be found (process exited before it was read, no image-load
    // event, no usable command line). BinaryPath is then "" — never the bare ImageName.
    public bool BinaryPathUnresolved { get; set; }
    public string CWD { get; set; } = "";
    public string TokenUser { get; set; } = "";
    public string IntegrityLevel { get; set; } = "";
    public bool IsProtected { get; set; }
    public List<string> FailedDllLookups { get; set; } = new();
    public List<string> LoadedDlls { get; set; } = new();
}
