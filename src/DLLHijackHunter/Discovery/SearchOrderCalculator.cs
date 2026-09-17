using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class SearchOrderCalculator
{
    private static readonly Lazy<bool> _safeDllSearchMode = new(GetSafeDllSearchMode);

    public static List<string> GetSearchOrder(string binaryPath, string dllName)
    {
        var order = new List<string>();
        string? binaryDir = Path.GetDirectoryName(binaryPath);

        if (string.IsNullOrEmpty(binaryDir)) return order;

        // Step 0: .local redirection (highest priority)
        string dotLocalDir = binaryPath + ".local";
        if (Directory.Exists(dotLocalDir))
        {
            order.Add(Path.Combine(dotLocalDir, dllName));
        }

        // Step 1: Application directory
        order.Add(Path.Combine(binaryDir, dllName));

        if (_safeDllSearchMode.Value)
        {
            // SafeDllSearchMode = ON (default on modern Windows)
            // System32 → System → Windows → CWD → PATH
            order.Add(Path.Combine(Environment.SystemDirectory, dllName));
            order.Add(Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.Windows), "System", dllName));
            order.Add(Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.Windows), dllName));
            order.Add("[CWD]\\" + dllName); // placeholder
        }
        else
        {
            // SafeDllSearchMode = OFF
            // CWD → System32 → System → Windows → PATH
            order.Insert(1, "[CWD]\\" + dllName); // CWD right after app dir
            order.Add(Path.Combine(Environment.SystemDirectory, dllName));
            order.Add(Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.Windows), "System", dllName));
            order.Add(Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.Windows), dllName));
        }

        // PATH directories
        // HEURISTIC WARNING: Using the current scanning process's PATH.
        // The actual PATH during execution heavily depends on the context (e.g. SYSTEM vs User).
        // This is a best-effort estimation and may overstate search-order accuracy.
        var pathDirs = Environment.GetEnvironmentVariable("PATH")?.Split(';',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (pathDirs != null)
        {
            foreach (var dir in pathDirs)
            {
                if (!string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir))
                    order.Add(Path.Combine(dir, dllName));
            }
        }

        return order;
    }

    /// <summary>
    /// Find the first path in search order where the DLL actually exists.
    /// Returns null for phantom DLLs.
    /// </summary>
    public static string? FindActualDllLocation(string binaryPath, string dllName)
    {
        var order = GetSearchOrder(binaryPath, dllName);
        return order.FirstOrDefault(p => !p.StartsWith("[CWD]") && File.Exists(p));
    }

    /// <summary>
    /// Find writable positions in the search order that come BEFORE the actual DLL.
    /// Writability is judged for an unprivileged attacker (optionally also the target's
    /// non-privileged RunAsAccount), never for the elevated token running this tool.
    /// </summary>
    public static List<string> FindHijackablePositions(string binaryPath, string dllName,
        string? runAsAccount = null)
    {
        var order = GetSearchOrder(binaryPath, dllName);
        string? actualLocation = FindActualDllLocation(binaryPath, dllName);
        var hijackable = new List<string>();

        foreach (var path in order)
        {
            if (path.StartsWith("[CWD]")) continue;

            // If DLL exists at this position, check whether the directory is also writable
            // (overwrite attack — attacker replaces the existing legitimate copy in place).
            // Then stop: no search-order position after the legitimate DLL is hijackable.
            if (actualLocation != null &&
                path.Equals(actualLocation, StringComparison.OrdinalIgnoreCase))
            {
                string? existingDir = Path.GetDirectoryName(path);
                if (existingDir != null &&
                    Native.AclChecker.IsDirectoryWritableByStandardUser(existingDir, runAsAccount))
                    hijackable.Add(path); // directory writable → DLL itself can be overwritten
                break;
            }

            // Check if an unprivileged attacker can write to this location
            // (plant a DLL before the legitimate copy is found).
            string? dir = Path.GetDirectoryName(path);
            if (dir != null && Native.AclChecker.IsDirectoryWritableByStandardUser(dir, runAsAccount))
            {
                hijackable.Add(path);
            }
        }

        return hijackable;
    }

    private static bool GetSafeDllSearchMode()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager");
            var val = key?.GetValue("SafeDllSearchMode");
            return val == null || (int)val != 0;
        }
        catch
        {
            return true; // default ON
        }
    }
}