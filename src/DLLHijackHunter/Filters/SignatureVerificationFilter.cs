using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;
using Microsoft.Win32;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace DLLHijackHunter.Filters;

/// <summary>
/// SOFT GATE: Protected Process Light (PPL) enforces DLL signature at kernel level.
/// Non-PPL signature checks run AFTER DllMain — our code already executed.
/// </summary>
public class SignatureVerificationFilter : ISoftGate
{
    public string Name => "Signature Verification / PPL";

    // Binaries known to run as PPL
    private static readonly HashSet<string> KnownPPLBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "smss.exe", "lsass.exe", "services.exe",
        "wininit.exe", "MsMpEng.exe", "SenseIR.exe",
        "SecurityHealthService.exe", "svchost.exe" // svchost CAN be PPL for specific services
    };

    public (double penalty, string? reason) Evaluate(HijackCandidate candidate)
    {
        string binaryName = Path.GetFileName(candidate.BinaryPath).ToLowerInvariant();

        // Check for PPL binary
        if (KnownPPLBinaries.Contains(binaryName))
        {
            // svchost is PPL for SOME services, not all
            if (binaryName == "svchost.exe")
            {
                // Check if this specific service is PPL
                bool isPPLService = IsServicePPL(candidate.TriggerIdentifier);
                if (isPPLService)
                {
                    candidate.IsProtectedProcess = true;
                    candidate.FilterResults["Signature"] = FilterResult.Failed;
                    return (45, $"Service {candidate.TriggerIdentifier} runs under PPL svchost. " +
                               "Kernel enforces DLL signature. Requires PPL bypass.");
                }

                candidate.FilterResults["Signature"] = FilterResult.Passed;
                return (0, null);
            }

            candidate.IsProtectedProcess = true;
            candidate.FilterResults["Signature"] = FilterResult.Failed;
            return (45, $"{binaryName} is in the tool's hardcoded Protected Process Light (PPL) list. " +
                       "Kernel enforces DLL signature verification if truly PPL.");
        }

        // Service not in the hardcoded binary list (third-party security products, new
        // Windows PPL services, svchost ServiceDll contexts): ask the SCM configuration.
        if (candidate.Trigger == TriggerType.Service && IsServicePPL(candidate.TriggerIdentifier))
        {
            candidate.IsProtectedProcess = true;
            candidate.FilterResults["Signature"] = FilterResult.Failed;
            return (45, $"Service {candidate.TriggerIdentifier} is configured as a protected " +
                       "service (LaunchProtected). Kernel enforces DLL signature. Requires PPL bypass.");
        }

        // For non-PPL: even if binary calls WinVerifyTrust, DllMain runs FIRST
        // But check for FORCE_INTEGRITY DllCharacteristic
        try
        {
            var pe = PEAnalyzer.Analyze(candidate.BinaryPath);
            if (pe.ForceIntegrity)
            {
                candidate.IsProtectedProcess = true;
                candidate.FilterResults["Signature"] = FilterResult.Failed;
                return (40, $"{binaryName} has FORCE_INTEGRITY DllCharacteristic set. " +
                           "Kernel enforces code integrity for all loaded modules.");
            }
        }
        catch { }

        candidate.FilterResults["Signature"] = FilterResult.Passed;
        return (0, null);
    }

    // Services known to run as PPL (fast path; the registry check below is authoritative
    // for anything not listed).
    private static readonly HashSet<string> KnownPPLServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "WinDefend", "SecurityHealthService", "Sense",
        "SgrmBroker", "KeyIso", "SamSs"
    };

    private static readonly ConcurrentDictionary<string, bool> _launchProtectedCache =
        new(StringComparer.OrdinalIgnoreCase);

    private static bool IsServicePPL(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName)) return false;
        if (KnownPPLServices.Contains(serviceName)) return true;

        return _launchProtectedCache.GetOrAdd(serviceName, IsLaunchProtected);
    }

    /// <summary>
    /// HKLM\SYSTEM\CurrentControlSet\Services\{name}\LaunchProtected (DWORD):
    /// 0 = none, 1 = Windows, 2 = WindowsLight, 3 = AntimalwareLight. Nonzero means the SCM
    /// starts the service as a protected process — readable without the service running.
    /// </summary>
    private static bool IsLaunchProtected(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            return key?.GetValue("LaunchProtected") is int level && level != 0;
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"LaunchProtected lookup failed for service '{serviceName}': {ex.Message}");
            return false;
        }
    }
}