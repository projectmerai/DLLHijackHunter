using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class StartupItemEnumerator
{
    private static readonly string[] RunKeyPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    };

    public static List<DiscoveryContext> EnumerateStartupItems()
    {
        var results = new List<DiscoveryContext>();

        // HKLM Run keys run as the interactively logged-on user (NOT SYSTEM)
        foreach (var keyPath in RunKeyPaths)
        {
            EnumerateRunKey(Registry.LocalMachine, keyPath,
                "Interactive User", results);
        }

        // Per-user Run keys and Startup folders for EVERY user profile, each attributed to
        // its owner. Using HKCU / SpecialFolder.Startup alone would only see the scanner's
        // own account — after over-the-shoulder elevation that is the admin, not the users
        // whose logon actually triggers these entries.
        EnumeratePerUserStartup(results);

        // Common Startup folder runs programs as each user who logs on (NOT SYSTEM)
        EnumerateStartupFolder(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            "Interactive User", results);

        // AppInit_DLLs
        EnumerateAppInitDlls(results);

        // AppCertDlls
        EnumerateAppCertDlls(results);

        // IFEO
        EnumerateIFEO(results);

        return results;
    }

    private static void EnumeratePerUserStartup(List<DiscoveryContext> results)
    {
        var coveredHives = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var coveredFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Loaded user hives under HKEY_USERS (interactive users currently logged on).
        try
        {
            foreach (var sid in Registry.Users.GetSubKeyNames())
            {
                if (!IsUserProfileSid(sid)) continue;
                try
                {
                    using var hive = Registry.Users.OpenSubKey(sid);
                    if (hive == null) continue;
                    string account = ResolveAccount(sid);
                    foreach (var keyPath in RunKeyPaths)
                        EnumerateRunKey(hive, keyPath, account, results);
                    coveredHives.Add(sid);
                }
                catch (Exception ex)
                {
                    ScanLogger.Debug($"Could not read Run keys for {sid}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"Could not enumerate HKEY_USERS: {ex.Message}");
        }

        // 2. Per-user Startup folders for every local profile (no hive load needed).
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (profileList != null)
            {
                foreach (var sid in profileList.GetSubKeyNames())
                {
                    if (!IsUserProfileSid(sid)) continue;
                    using var profileKey = profileList.OpenSubKey(sid);
                    if (profileKey?.GetValue("ProfileImagePath") is not string profilePath) continue;

                    string startup = Path.Combine(Environment.ExpandEnvironmentVariables(profilePath),
                        @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");
                    if (coveredFolders.Add(startup))
                        EnumerateStartupFolder(startup, ResolveAccount(sid), results);
                }
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"Could not enumerate profile Startup folders: {ex.Message}");
        }

        // 3. Fallback for the scanner's own account (e.g. HKEY_USERS not readable when the
        //    tool runs unelevated, or a roaming/redirected Startup folder).
        string currentUser = Native.TokenHelper.GetCurrentUsername();
        string? currentSid = null;
        try { currentSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value; } catch { }
        if (currentSid == null || !coveredHives.Contains(currentSid))
        {
            foreach (var keyPath in RunKeyPaths)
                EnumerateRunKey(Registry.CurrentUser, keyPath, currentUser, results);
        }

        string ownStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrEmpty(ownStartup) && coveredFolders.Add(ownStartup))
            EnumerateStartupFolder(ownStartup, currentUser, results);
    }

    // Real user accounts are S-1-5-21-<domain>-<rid> (skip *_Classes, .DEFAULT, service SIDs).
    private static bool IsUserProfileSid(string sid) =>
        sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
        !sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase);

    private static string ResolveAccount(string sid)
    {
        try
        {
            return new System.Security.Principal.SecurityIdentifier(sid)
                .Translate(typeof(System.Security.Principal.NTAccount)).Value;
        }
        catch
        {
            return sid;
        }
    }

    private static void EnumerateRunKey(RegistryKey root, string keyPath,
        string runAs, List<DiscoveryContext> results)
    {
        try
        {
            using var key = root.OpenSubKey(keyPath);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName) as string;
                if (string.IsNullOrEmpty(value)) continue;

                string binaryPath = ParseCommandPath(value);
                if (!File.Exists(binaryPath)) continue;

                results.Add(new DiscoveryContext
                {
                    BinaryPath = binaryPath,
                    TriggerType = TriggerType.RunKey,
                    TriggerIdentifier = $"{root.Name}\\{keyPath}\\{valueName}",
                    DisplayName = valueName,
                    RunAsAccount = runAs,
                    IsAutoStart = true
                });
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"Run key enumeration failed for {root.Name}\\{keyPath}: {ex.Message}");
        }
    }

    private static void EnumerateStartupFolder(string folderPath, string runAs,
        List<DiscoveryContext> results)
    {
        if (!Directory.Exists(folderPath)) return;

        try
        {
            foreach (var file in Directory.GetFiles(folderPath))
            {
                string ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".exe" or ".bat" or ".cmd" or ".vbs" or ".js" or ".lnk")
                {
                    string binaryPath = file;
                    if (ext == ".lnk")
                    {
                        try
                        {
                            Type? t = Type.GetTypeFromProgID("WScript.Shell");
                            if (t != null)
                            {
                                object shell = Activator.CreateInstance(t)!;
                                object shortcut = t.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { file })!;
                                string target = (string)shortcut.GetType().InvokeMember("TargetPath", System.Reflection.BindingFlags.GetProperty, null, shortcut, null)!;
                                if (!string.IsNullOrEmpty(target))
                                {
                                    binaryPath = target;
                                }
                            }
                        }
                        catch { /* Fallback to file path if resolution fails */ }
                    }

                    results.Add(new DiscoveryContext
                    {
                        BinaryPath = binaryPath,
                        TriggerType = TriggerType.Startup,
                        TriggerIdentifier = file,
                        DisplayName = Path.GetFileNameWithoutExtension(file),
                        RunAsAccount = runAs,
                        IsAutoStart = true
                    });
                }
            }
        }
        catch { }
    }

    private static void EnumerateAppInitDlls(List<DiscoveryContext> results)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
            if (key == null) return;

            var loadAppInit = key.GetValue("LoadAppInit_DLLs");
            if (loadAppInit == null || (int)loadAppInit == 0) return;

            var appInitDlls = key.GetValue("AppInit_DLLs") as string;
            if (string.IsNullOrEmpty(appInitDlls)) return;

            // AppInit_DLLs is a space-delimited or comma-delimited list of DLL paths.
            // Each DLL is injected into every user-mode process that loads user32.dll.
            var dllPaths = appInitDlls.Split(new[] { ' ', ',' },
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            foreach (var rawDllPath in dllPaths)
            {
                string dllPath = Environment.ExpandEnvironmentVariables(rawDllPath.Trim('"'));

                results.Add(new DiscoveryContext
                {
                    BinaryPath = dllPath,
                    TriggerType = TriggerType.Startup,
                    TriggerIdentifier = "AppInit_DLLs",
                    DisplayName = "AppInit_DLLs: " + Path.GetFileName(dllPath),
                    RunAsAccount = "ALL_PROCESSES",
                    IsAutoStart = true
                });
            }
        }
        catch { }
    }

    private static void EnumerateAppCertDlls(List<DiscoveryContext> results)
    {
        try
        {
            // Every DLL listed here is loaded into any process that calls CreateProcess,
            // CreateProcessAsUser, CreateProcessWithLogonW or WinExec — i.e. virtually every
            // process. The value name is arbitrary; the value data is the DLL path. An attacker
            // who can write the referenced DLL gets code execution in those processes.
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls");
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                if (key.GetValue(valueName) is not string rawDllPath ||
                    string.IsNullOrWhiteSpace(rawDllPath))
                    continue;

                string dllPath = Environment.ExpandEnvironmentVariables(rawDllPath.Trim().Trim('"'));

                results.Add(new DiscoveryContext
                {
                    BinaryPath = dllPath,
                    TriggerType = TriggerType.Startup,
                    TriggerIdentifier = "AppCertDlls",
                    DisplayName = "AppCertDlls: " + Path.GetFileName(dllPath),
                    RunAsAccount = "ALL_PROCESSES",
                    IsAutoStart = true
                });
            }
        }
        catch { }
    }

    private static void EnumerateIFEO(List<DiscoveryContext> results)
    {
        try
        {
            using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (ifeoKey == null) return;

            foreach (var subkeyName in ifeoKey.GetSubKeyNames())
            {
                using var subkey = ifeoKey.OpenSubKey(subkeyName);
                if (subkey == null) continue;

                var debugger = subkey.GetValue("Debugger") as string;
                // Note: GlobalFlag is debug metadata; IFEO persistence uses Debugger
                // (above) or SilentProcessExit (below) — not GlobalFlag directly.

                if (!string.IsNullOrEmpty(debugger))
                {
                    results.Add(new DiscoveryContext
                    {
                        BinaryPath = ParseCommandPath(debugger),
                        TriggerType = TriggerType.Startup,
                        TriggerIdentifier = $"IFEO\\{subkeyName}",
                        DisplayName = $"IFEO Debugger for {subkeyName}",
                        RunAsAccount = "VARIES",
                        IsAutoStart = true
                    });
                }

                // SilentProcessExit (T1546.012): when the monitored image exits,
                // Windows launches MonitorProcess — typically as the user or service
                // account that triggered the exit. A writable MonitorProcess binary
                // is a persistence and/or LPE vector.
                try
                {
                    using var exitKey = subkey.OpenSubKey("SilentProcessExit");
                    if (exitKey != null)
                    {
                        var monitorProcess = exitKey.GetValue("MonitorProcess") as string;
                        if (!string.IsNullOrEmpty(monitorProcess))
                        {
                            results.Add(new DiscoveryContext
                            {
                                BinaryPath = ParseCommandPath(monitorProcess),
                                TriggerType = TriggerType.Startup,
                                TriggerIdentifier = $"IFEO\\{subkeyName}\\SilentProcessExit",
                                DisplayName = $"IFEO SilentProcessExit Monitor for {subkeyName}",
                                RunAsAccount = "VARIES",
                                IsAutoStart = true
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static string ParseCommandPath(string command)
    {
        command = command.Trim();
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            if (end > 0) return command[1..end];
        }

        string expanded = Environment.ExpandEnvironmentVariables(command);
        // Note: Simple split on space breaks on unquoted paths with spaces
        string path = CommandLineParser.ExtractExecutablePath(expanded);
        return path.Trim('"');
    }
}