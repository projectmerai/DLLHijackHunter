using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class ServiceEnumerator
{
    public static List<DiscoveryContext> EnumerateServices()
    {
        var results = new List<DiscoveryContext>();

        try
        {
            using var scm = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (scm == null) return results;

            foreach (string serviceName in scm.GetSubKeyNames())
            {
                try
                {
                    using var serviceKey = scm.OpenSubKey(serviceName);
                    if (serviceKey == null) continue;

                    var imagePathRaw = serviceKey.GetValue("ImagePath") as string;
                    if (string.IsNullOrEmpty(imagePathRaw)) continue;

                    string binaryPath = ParseServiceImagePath(imagePathRaw);

                    if (!File.Exists(binaryPath)) continue;

                    var startType = serviceKey.GetValue("Start");
                    var objectName = serviceKey.GetValue("ObjectName") as string ?? "LocalSystem";
                    var displayName = serviceKey.GetValue("DisplayName") as string ?? serviceName;

                    int startTypeInt = startType != null ? (int)startType : 3;

                    string startTypeStr = startTypeInt switch
                    {
                        0 => "BOOT_START",
                        1 => "SYSTEM_START",
                        2 => "AUTO_START",
                        3 => "DEMAND_START",
                        4 => "DISABLED",
                        _ => "UNKNOWN"
                    };

                    bool isSvchost = imagePathRaw.Contains("svchost.exe",
                        StringComparison.OrdinalIgnoreCase);

                    // Add the main binary execution context
                    results.Add(new DiscoveryContext
                    {
                        BinaryPath = binaryPath,
                        TriggerType = TriggerType.Service,
                        TriggerIdentifier = serviceName,
                        DisplayName = displayName,
                        RunAsAccount = NormalizeAccountName(objectName),
                        StartType = startTypeStr,
                        IsAutoStart = startTypeInt <= 2,
                        IsSvchostService = isSvchost
                    });

                    // For svchost services, also enumerate the actual service DLL
                    if (isSvchost)
                    {
                        string? serviceDll = SvchostResolver.GetServiceDll(serviceName);
                        if (!string.IsNullOrEmpty(serviceDll) && File.Exists(serviceDll))
                        {
                            results.Add(new DiscoveryContext
                            {
                                BinaryPath = serviceDll,
                                TriggerType = TriggerType.Service,
                                TriggerIdentifier = serviceName,
                                DisplayName = displayName + " [ServiceDll]",
                                RunAsAccount = NormalizeAccountName(objectName),
                                StartType = startTypeStr,
                                IsAutoStart = startTypeInt <= 2,
                                IsSvchostService = true
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    ScanLogger.Debug($"Service enumeration failed for '{serviceName}': {ex.Message}");
                    continue;
                }
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"Service enumeration failed: {ex.Message}");
        }

        return results;
    }

    private static string ParseServiceImagePath(string imagePath)
    {
        imagePath = imagePath.Trim();

        // Expand environment variables first (before quote stripping)
        imagePath = Environment.ExpandEnvironmentVariables(imagePath);

        // Handle quoted paths
        if (imagePath.StartsWith('"'))
        {
            int end = imagePath.IndexOf('"', 1);
            if (end > 0) return imagePath[1..end];
        }

        // Use the shared parser to handle quotes and arguments correctly
        return CommandLineParser.ExtractExecutablePath(imagePath);
    }

    private static string NormalizeAccountName(string account)
    {
        if (string.IsNullOrEmpty(account)) return "NT AUTHORITY\\SYSTEM";

        return account.ToUpperInvariant() switch
        {
            "LOCALSYSTEM" or "" => "NT AUTHORITY\\SYSTEM",
            "NT AUTHORITY\\LOCALSERVICE" => "NT AUTHORITY\\LOCAL SERVICE",
            "NT AUTHORITY\\NETWORKSERVICE" => "NT AUTHORITY\\NETWORK SERVICE",
            _ => account
        };
    }
}