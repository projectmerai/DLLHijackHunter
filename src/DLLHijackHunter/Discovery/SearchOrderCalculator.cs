using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class SearchOrderCalculator
{
    private static readonly Lazy<bool> _safeDllSearchMode = new(GetSafeDllSearchMode);

    // The machine-wide PATH (HKLM ...\Session Manager\Environment\Path). Services and
    // SYSTEM tasks get ONLY this PATH; the scanner's own %PATH% additionally contains the
    // interactive user's per-user PATH entries, which a service never searches.
    private static readonly Lazy<string[]?> _machinePathDirs = new(GetMachinePathDirs);

    public static List<string> GetSearchOrder(string binaryPath, string dllName)
        => GetSearchOrder(binaryPath, dllName, GetProcessPathDirs());

    private static List<string> GetSearchOrder(string binaryPath, string dllName, string[]? pathDirs)
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

        // PATH directories — the caller supplies the PATH appropriate to the target's
        // identity (machine PATH for service accounts, scanner PATH otherwise).
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
        // A service-account target only ever searches the machine PATH; using the scanner's
        // PATH would add per-user PATH directories (e.g. C:\Python311 from the admin's
        // user PATH) that the target never consults — false-positive hijack positions.
        string[]? pathDirs = GetPathDirsFor(runAsAccount);

        var order = GetSearchOrder(binaryPath, dllName, pathDirs);
        string? actualLocation = order.FirstOrDefault(p => !p.StartsWith("[CWD]") && File.Exists(p));
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

    /// <summary>
    /// Like <see cref="FindActualDllLocation(string, string)"/> but evaluated with the PATH the
    /// target identity actually sees (machine PATH for service accounts).
    /// </summary>
    internal static string? FindActualDllLocation(string binaryPath, string dllName, string? runAsAccount)
    {
        var order = GetSearchOrder(binaryPath, dllName, GetPathDirsFor(runAsAccount));
        return order.FirstOrDefault(p => !p.StartsWith("[CWD]") && File.Exists(p));
    }

    /// <summary>
    /// The PATH directories a process running as <paramref name="runAsAccount"/> searches:
    /// the machine-wide PATH for SYSTEM / LOCAL SERVICE / NETWORK SERVICE, otherwise the
    /// scanner's PATH (machine PATH + the interactive user's per-user PATH).
    /// </summary>
    internal static string[]? GetPathDirsFor(string? runAsAccount) =>
        IsServiceAccount(runAsAccount)
            ? (_machinePathDirs.Value ?? GetProcessPathDirs())
            : GetProcessPathDirs();

    private static string[]? GetProcessPathDirs() =>
        Environment.GetEnvironmentVariable("PATH")?.Split(';',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static bool IsServiceAccount(string? account)
    {
        if (string.IsNullOrWhiteSpace(account)) return false;
        return account.ToUpperInvariant() is
            "NT AUTHORITY\\SYSTEM" or "LOCALSYSTEM" or "SYSTEM" or
            "NT AUTHORITY\\LOCAL SERVICE" or "NT AUTHORITY\\NETWORK SERVICE";
    }

    private static string[]? GetMachinePathDirs()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
            // Path is REG_EXPAND_SZ; read raw and expand (%SystemRoot% etc. are machine-wide).
            if (key?.GetValue("Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames)
                is not string raw || string.IsNullOrWhiteSpace(raw))
                return null;

            return Environment.ExpandEnvironmentVariables(raw).Split(';',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"Could not read machine PATH, falling back to process PATH: {ex.Message}");
            return null; // caller falls back to the process PATH
        }
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