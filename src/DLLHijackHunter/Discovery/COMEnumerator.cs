using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class COMEnumerator
{
    public static List<DiscoveryContext> EnumerateCOMObjects()
    {
        var results = new List<DiscoveryContext>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var clsidKey = Registry.ClassesRoot.OpenSubKey("CLSID");
            if (clsidKey == null) return results;

            foreach (var clsid in clsidKey.GetSubKeyNames())
            {
                try
                {
                    // Check InprocServer32 (DLL-based COM objects)
                    EnumerateComServer(clsidKey, clsid, "InprocServer32", seen, results);

                    // Check LocalServer32 (EXE-based COM objects)
                    EnumerateComServer(clsidKey, clsid, "LocalServer32", seen, results);
                }
                catch { continue; }
            }
        }
        catch { }

        return results;
    }

    private static void EnumerateComServer(RegistryKey clsidKey, string clsid,
        string serverType, HashSet<string> seen, List<DiscoveryContext> results)
    {
        using var serverKey = clsidKey.OpenSubKey($"{clsid}\\{serverType}");
        if (serverKey == null) return;

        var serverPath = serverKey.GetValue(null) as string;
        if (string.IsNullOrEmpty(serverPath)) return;

        // LocalServer32 values are full command lines (e.g. "C:\Program Files\Foo\bar.exe" /sta).
        // Always parse through CommandLineParser so the executable path is correctly extracted
        // regardless of quoting — Trim('"\') alone corrupts quoted-path-with-args strings.
        // InprocServer32 values are plain DLL paths (quoted or bare); Trim('"\') is safe there.
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

        if (seen.Contains(expanded)) return;
        seen.Add(expanded);

        // Get display name
        using var nameKey = clsidKey.OpenSubKey(clsid);
        var displayName = nameKey?.GetValue(null) as string ?? clsid;

        if (File.Exists(expanded))
        {
            results.Add(new DiscoveryContext
            {
                BinaryPath = expanded,
                TriggerType = TriggerType.COM,
                TriggerIdentifier = clsid,
                DisplayName = $"{displayName} [{serverType}]",
                RunAsAccount = "VARIES",
                IsAutoStart = false
            });
        }
        else
        {
            // COM server doesn't exist — phantom COM hijack!
            results.Add(new DiscoveryContext
            {
                BinaryPath = expanded,
                TriggerType = TriggerType.COM,
                TriggerIdentifier = clsid,
                DisplayName = $"[PHANTOM COM] {displayName} [{serverType}]",
                RunAsAccount = "VARIES",
                IsAutoStart = false
            });
        }
    }
}