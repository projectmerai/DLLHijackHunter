using DLLHijackHunter.Models;
using Microsoft.Win32;
using System.Collections.Concurrent;

namespace DLLHijackHunter.Discovery;

public static class AutoElevateEnumerator
{
    public static List<DiscoveryContext> EnumerateAutoElevateBinaries()
    {
        var results = new ConcurrentBag<DiscoveryContext>();

        // 1. Scan EXEs for AutoElevate Manifests
        string system32 = Environment.SystemDirectory;
        string syswow64 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

        ScanDirectory(system32, results);

        if (Directory.Exists(syswow64) &&
            !string.Equals(system32, syswow64, StringComparison.OrdinalIgnoreCase))
        {
            ScanDirectory(syswow64, results);
        }

        // 2. Scan COM Objects for Elevation\Enabled=1
        ScanComElevation(results);

        return results.ToList();
    }

    private static void ScanDirectory(string directory, ConcurrentBag<DiscoveryContext> results)
    {
        try
        {
            var files = Directory.EnumerateFiles(directory, "*.exe", SearchOption.TopDirectoryOnly);

            Parallel.ForEach(files, file =>
            {
                if (IsAutoElevate(file))
                {
                    results.Add(new DiscoveryContext
                    {
                        BinaryPath = file,
                        TriggerType = TriggerType.UACBypass,
                        TriggerIdentifier = "Manifest AutoElevate (Heuristic)",
                        DisplayName = Path.GetFileName(file),
                        RunAsAccount = "HIGH_INTEGRITY\\CurrentUser",
                        StartType = "MANUAL",
                        IsAutoStart = false
                    });
                }
            });
        }
        catch { }
    }

    /// <summary>
    /// Scans HKLM\SOFTWARE\Classes\CLSID for COM objects with Elevation\Enabled=1.
    /// These are hidden UAC bypass vectors (Fodhelper, CMSTPLUA, etc.).
    /// COM elevation grants High Integrity to the current user — NOT SYSTEM.
    /// </summary>
    private static void ScanComElevation(ConcurrentBag<DiscoveryContext> results)
    {
        try
        {
            using var clsidKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\CLSID");
            if (clsidKey == null) return;

            foreach (var clsid in clsidKey.GetSubKeyNames())
            {
                try
                {
                    using var elevationKey = clsidKey.OpenSubKey($@"{clsid}\Elevation");
                    if (elevationKey == null) continue;

                    var enabled = elevationKey.GetValue("Enabled");
                    if (enabled == null || (int)enabled != 1) continue;

                    // Check InprocServer32 (DLL-based COM objects)
                    TryAddComServer(clsidKey, clsid, "InprocServer32", results);

                    // Check LocalServer32 (EXE-based COM objects, e.g. Fodhelper)
                    TryAddComServer(clsidKey, clsid, "LocalServer32", results);
                }
                catch { continue; }
            }
        }
        catch { }
    }

    private static void TryAddComServer(RegistryKey clsidKey, string clsid,
        string serverType, ConcurrentBag<DiscoveryContext> results)
    {
        try
        {
            using var serverKey = clsidKey.OpenSubKey($@"{clsid}\{serverType}");
            var serverPath = serverKey?.GetValue(null) as string;

            if (string.IsNullOrEmpty(serverPath)) return;

            // LocalServer32 values are full command lines (e.g. "C:\Program Files\Foo\bar.exe" /sta).
            // Always parse through CommandLineParser so the executable path is correctly extracted
            // regardless of quoting — Trim('"') alone corrupts quoted-path-with-args strings.
            // InprocServer32 values are plain DLL paths (quoted or bare); Trim('"') is safe there.
            string expanded;
            if (serverType == "LocalServer32")
            {
                expanded = CommandLineParser.ExtractExecutablePath(
                    Environment.ExpandEnvironmentVariables(serverPath));
            }
            else
            {
                expanded = Environment.ExpandEnvironmentVariables(serverPath).Trim('"');
            }

            if (!File.Exists(expanded)) return;

            results.Add(new DiscoveryContext
            {
                BinaryPath = expanded,
                TriggerType = TriggerType.UACBypass,
                TriggerIdentifier = $"COM AutoElevate ({clsid})",
                DisplayName = $"{Path.GetFileName(expanded)} [{serverType}]",
                RunAsAccount = "HIGH_INTEGRITY\\CurrentUser",
                StartType = "COM_INSTANTIATION",
                IsAutoStart = false
            });
        }
        catch { }
    }

    /// <summary>
    /// Detects <c>&lt;autoElevate&gt;true&lt;/autoElevate&gt;</c> in the binary's
    /// embedded manifest. Uses <see cref="PEAnalyzer"/>, which tries PeNet's RT_MANIFEST
    /// resource extraction first and falls back to a raw-byte scan — so manifest content
    /// is parsed consistently across the whole tool rather than re-read here separately.
    /// </summary>
    private static bool IsAutoElevate(string filePath)
    {
        try
        {
            var pe = PEAnalyzer.Analyze(filePath);
            if (pe.AnalysisError != null) return false;

            // PEAnalyzer.CheckForManifest runs: (1) PeNet RT_MANIFEST resource parse,
            // (2) raw-byte fallback, (3) external .manifest file. Reuse its result
            // rather than opening the file a second time.
            return !string.IsNullOrEmpty(pe.ManifestContent) &&
                   pe.ManifestContent.Contains(
                       "<autoElevate>true</autoElevate>",
                       StringComparison.OrdinalIgnoreCase);
        }
        catch { }
        return false;
    }
}