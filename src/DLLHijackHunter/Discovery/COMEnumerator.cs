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

        string runAs = ResolveRunAsAccount(nameKey, serverType);

        if (File.Exists(expanded))
        {
            results.Add(new DiscoveryContext
            {
                BinaryPath = expanded,
                TriggerType = TriggerType.COM,
                TriggerIdentifier = clsid,
                DisplayName = $"{displayName} [{serverType}]",
                RunAsAccount = runAs,
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
                RunAsAccount = runAs,
                IsAutoStart = false
            });
        }
    }

    /// <summary>
    /// Determine the identity a COM server runs as.
    ///
    /// InprocServer32 DLLs are mapped into whichever client activates them, so their
    /// identity genuinely depends on the caller — "VARIES" is kept for them.
    ///
    /// LocalServer32 EXEs are launched by the COM SCM using the AppID configuration:
    ///   HKCR\CLSID\{clsid}  (value "AppID")  →  HKLM\SOFTWARE\Classes\AppID\{appid}
    ///     • "LocalService" = the server is an NT service → that service's ObjectName
    ///     • "RunAs"        = explicit account ("nt authority\system", "Interactive User", …)
    ///     • neither        = activated as the launching (calling) user
    /// </summary>
    private static string ResolveRunAsAccount(RegistryKey? clsidSubKey, string serverType)
    {
        if (serverType != "LocalServer32")
            return "VARIES";

        const string LaunchingUser = "Launching User";

        try
        {
            if (clsidSubKey?.GetValue("AppID") is not string appId || string.IsNullOrWhiteSpace(appId))
                return LaunchingUser;

            appId = appId.Trim();
            if (!appId.StartsWith('{')) appId = "{" + appId.Trim('{', '}') + "}";

            using var appIdKey = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\AppID\{appId}");
            if (appIdKey == null) return LaunchingUser;

            // COM server hosted as a Windows service: it runs as that service's account.
            if (appIdKey.GetValue("LocalService") is string localService &&
                !string.IsNullOrWhiteSpace(localService))
            {
                using var svcKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{localService.Trim()}");
                string objectName = svcKey?.GetValue("ObjectName") as string ?? "LocalSystem";
                return NormalizeAccountName(objectName);
            }

            if (appIdKey.GetValue("RunAs") is string runAs && !string.IsNullOrWhiteSpace(runAs))
                return NormalizeAccountName(runAs.Trim());
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"COM AppID RunAs lookup failed: {ex.Message}");
        }

        return LaunchingUser;
    }

    /// <summary>
    /// Normalize to the canonical spellings PrivilegeDeltaFilter / TieredScorer / AclChecker
    /// match on (same patterns as ServiceEnumerator, plus the forms seen in AppID RunAs).
    /// </summary>
    private static string NormalizeAccountName(string account)
    {
        if (string.IsNullOrEmpty(account)) return "NT AUTHORITY\\SYSTEM";

        return account.ToUpperInvariant() switch
        {
            "LOCALSYSTEM" or "SYSTEM" or "NT AUTHORITY\\SYSTEM" => "NT AUTHORITY\\SYSTEM",
            "NT AUTHORITY\\LOCALSERVICE" or "NT AUTHORITY\\LOCAL SERVICE" or "LOCAL SERVICE"
                => "NT AUTHORITY\\LOCAL SERVICE",
            "NT AUTHORITY\\NETWORKSERVICE" or "NT AUTHORITY\\NETWORK SERVICE" or "NETWORK SERVICE"
                => "NT AUTHORITY\\NETWORK SERVICE",
            _ => account
        };
    }
}