using DLLHijackHunter.Models;
using Microsoft.Win32.TaskScheduler;

namespace DLLHijackHunter.Discovery;

public static class ScheduledTaskEnumerator
{
    public static List<DiscoveryContext> EnumerateScheduledTasks()
    {
        var results = new List<DiscoveryContext>();

        try
        {
            using var ts = new TaskService();
            if (ts.RootFolder != null)
            {
                EnumerateFolder(ts.RootFolder, results);
            }
        }
        catch { }

        return results;
    }

    private static void EnumerateFolder(TaskFolder folder, List<DiscoveryContext> results)
    {
        try
        {
            foreach (var task in folder.Tasks)
            {
                try
                {
                    if (task.Definition?.Actions == null) continue;

                    foreach (var action in task.Definition.Actions)
                    {
                        if (action is ExecAction execAction && !string.IsNullOrEmpty(execAction.Path))
                        {
                            string binaryPath = Environment.ExpandEnvironmentVariables(execAction.Path);
                            binaryPath = binaryPath.Trim('"');

                            if (!File.Exists(binaryPath)) continue;

                            var principal = task.Definition.Principal;
                            var logonType = principal?.LogonType ?? TaskLogonType.ServiceAccount;
                            bool runsElevated = principal?.RunLevel == TaskRunLevel.Highest;
                            string runAsAccount = ResolveTaskAccount(
                                principal?.UserId, principal?.GroupId, logonType, runsElevated);

                            // Determine repeat interval (first trigger that actually repeats)
                            TimeSpan? interval = null;
                            if (task.Definition.Triggers != null)
                            {
                                foreach (var trigger in task.Definition.Triggers)
                                {
                                    TimeSpan? repeat = trigger.Repetition?.Interval;
                                    if (repeat.HasValue && repeat.Value != TimeSpan.Zero)
                                    {
                                        interval = repeat;
                                        break;
                                    }
                                }
                            }

                            bool isAutoStart = task.Definition.Triggers?.Any(t =>
                                t is BootTrigger || t is LogonTrigger) ?? false;

                            results.Add(new DiscoveryContext
                            {
                                BinaryPath = binaryPath,
                                TriggerType = TriggerType.ScheduledTask,
                                TriggerIdentifier = task.Path,
                                DisplayName = task.Name,
                                RunAsAccount = runAsAccount,
                                IsAutoStart = isAutoStart,
                                RepeatInterval = interval
                            });

                            // Host-wrapped payloads (rundll32 x.dll,Entry / cmd /c x.exe /
                            // powershell -File x.ps1): the interesting binary is in the
                            // arguments, not the System32 host. Analyze it as well.
                            if (!string.IsNullOrWhiteSpace(execAction.Arguments))
                            {
                                string payload = CommandLineParser.ExtractExecutablePath(
                                    $"\"{binaryPath}\" {Environment.ExpandEnvironmentVariables(execAction.Arguments)}");
                                if (!string.IsNullOrEmpty(payload) &&
                                    !payload.Equals(binaryPath, StringComparison.OrdinalIgnoreCase) &&
                                    File.Exists(payload))
                                {
                                    results.Add(new DiscoveryContext
                                    {
                                        BinaryPath = payload,
                                        TriggerType = TriggerType.ScheduledTask,
                                        TriggerIdentifier = task.Path,
                                        DisplayName = $"{task.Name} [payload of {Path.GetFileName(binaryPath)}]",
                                        RunAsAccount = runAsAccount,
                                        IsAutoStart = isAutoStart,
                                        RepeatInterval = interval
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    ScanLogger.Debug($"Scheduled task enumeration failed for {task.Path}: {ex.Message}");
                    continue;
                }
            }

            foreach (var subfolder in folder.SubFolders)
            {
                EnumerateFolder(subfolder, results);
            }
        }
        catch (Exception ex)
        {
            ScanLogger.Debug($"Scheduled task folder enumeration failed for {folder.Path}: {ex.Message}");
        }
    }

    /// <summary>
    /// Resolve the identity a task actually runs as.
    /// • UserId may be a name ("SYSTEM", "NT AUTHORITY\\LocalService") or a SID string
    ///   ("S-1-5-18" is common in built-in tasks) — well-known SIDs are mapped regardless of
    ///   logon type, other SIDs are translated to an account name when possible.
    /// • A group principal (GroupId, no UserId) runs as whichever member logs on — never as
    ///   SYSTEM. Only the Administrators group with RunLevel=Highest runs elevated.
    /// • With neither set, only a ServiceAccount logon implies SYSTEM.
    /// </summary>
    private static string ResolveTaskAccount(string? userId, string? groupId,
        TaskLogonType logonType, bool runsElevated)
    {
        if (!string.IsNullOrWhiteSpace(userId))
            return NormalizeTaskAccount(userId.Trim());

        if (!string.IsNullOrWhiteSpace(groupId))
        {
            string group = TranslateSid(groupId.Trim());
            bool isAdmins = groupId.Trim().Equals("S-1-5-32-544", StringComparison.OrdinalIgnoreCase) ||
                            group.EndsWith("\\Administrators", StringComparison.OrdinalIgnoreCase) ||
                            group.Equals("Administrators", StringComparison.OrdinalIgnoreCase);
            return isAdmins && runsElevated
                ? "HIGH_INTEGRITY\\Interactive User"
                : "Interactive User";
        }

        return logonType == TaskLogonType.ServiceAccount
            ? "NT AUTHORITY\\SYSTEM"
            : "Interactive User";
    }

    private static string TranslateSid(string value)
    {
        if (!value.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return value;
        try
        {
            return new System.Security.Principal.SecurityIdentifier(value)
                .Translate(typeof(System.Security.Principal.NTAccount)).Value;
        }
        catch
        {
            return value; // unresolvable SID (deleted account, offline domain) — keep as-is
        }
    }

    private static string NormalizeTaskAccount(string account)
    {
        string upper = account.ToUpperInvariant();
        switch (upper)
        {
            case "S-1-5-18" or "SYSTEM" or "LOCALSYSTEM" or "NT AUTHORITY\\SYSTEM":
                return "NT AUTHORITY\\SYSTEM";
            case "S-1-5-19" or "LOCAL SERVICE" or "LOCALSERVICE" or
                 "NT AUTHORITY\\LOCAL SERVICE" or "NT AUTHORITY\\LOCALSERVICE":
                return "NT AUTHORITY\\LOCAL SERVICE";
            case "S-1-5-20" or "NETWORK SERVICE" or "NETWORKSERVICE" or
                 "NT AUTHORITY\\NETWORK SERVICE" or "NT AUTHORITY\\NETWORKSERVICE":
                return "NT AUTHORITY\\NETWORK SERVICE";
        }

        string translated = TranslateSid(account);
        return translated.Equals(account, StringComparison.Ordinal)
            ? account
            : NormalizeTaskAccount(translated);
    }
}
