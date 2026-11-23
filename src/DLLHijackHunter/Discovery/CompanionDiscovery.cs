using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

/// <summary>
/// Companion executables of services: EXEs a service may launch as children (e.g. a controller it
/// copies into its data directory), found read-only from the service's related directories.
/// Nothing is started, stopped or written: this only enumerates files and checks ACLs.
/// </summary>
internal static class CompanionDiscovery
{
    internal const string Source = "companion";

    internal sealed record ServiceEntry(string Name, string BinaryPath, string Account, string? ImagePath,
        IReadOnlyList<string> ParameterValues, string StartType = "AUTO_START");

    internal sealed record Companion(string ExePath, string Service, string Account, string Reason);

    /// <summary>F2: one executable (or skipped service) companion discovery looked at, kept or rejected, and why.</summary>
    internal sealed record Examined(string ExePath, string Service, bool Kept, string Reason);

    internal static (int examined, int kept, int rejected) Summarize(IEnumerable<Examined> report)
    {
        var list = report.Where(e => e.ExePath.Length > 0).ToList();
        return (list.Count, list.Count(e => e.Kept), list.Count(e => !e.Kept));
    }

    internal sealed class Env
    {
        public string[] ProgramFilesRoots { get; init; } = Array.Empty<string>();
        public string ProgramData { get; init; } = "";
        public string SystemRoot { get; init; } = "";
        public Func<string, string?, bool> IsDirWritable { get; init; } = (_, _) => false;
        public Func<string, (bool guarded, string reason)> Guard { get; init; } = _ => (false, "");

        /// <summary>The machine's real folders, the existing attacker-relative ACL check and the service guard.</summary>
        public static Env Real() => new()
        {
            ProgramFilesRoots = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                }
                .Where(p => !string.IsNullOrEmpty(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            SystemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            IsDirWritable = (dir, account) => Native.AclChecker.IsDirectoryWritableByStandardUser(dir, account),
            Guard = Safety.ServiceControl.Guard,
        };
    }

    /// <summary>LocalSystem, LocalService and NetworkService, in any of their spellings.</summary>
    internal static string? NormalizeServiceAccount(string account)
    {
        string a = (account ?? "").Trim().ToUpperInvariant();
        return a switch
        {
            "" or "LOCALSYSTEM" or "NT AUTHORITY\\SYSTEM" or ".\\LOCALSYSTEM" => "NT AUTHORITY\\SYSTEM",
            "NT AUTHORITY\\LOCALSERVICE" or "NT AUTHORITY\\LOCAL SERVICE" => "NT AUTHORITY\\LOCAL SERVICE",
            "NT AUTHORITY\\NETWORKSERVICE" or "NT AUTHORITY\\NETWORK SERVICE" => "NT AUTHORITY\\NETWORK SERVICE",
            _ => null
        };
    }

    private static string Trim(string p) => p.TrimEnd('\\', '/');

    private static bool IsUnder(string path, string root) =>
        root.Length > 0 && (Trim(path).Equals(Trim(root), StringComparison.OrdinalIgnoreCase) ||
                            Trim(path).StartsWith(Trim(root) + "\\", StringComparison.OrdinalIgnoreCase));

    /// <summary>The first folder below a Program Files root on the binary's path ("vendor"), and that root.</summary>
    private static (string root, string vendor)? VendorOf(string binaryPath, Env env)
    {
        foreach (var pf in env.ProgramFilesRoots)
        {
            if (string.IsNullOrEmpty(pf) || !IsUnder(binaryPath, pf)) continue;
            string rest = Trim(binaryPath).Substring(Trim(pf).Length).TrimStart('\\');
            int slash = rest.IndexOf('\\');
            if (slash <= 0) return null;   // binary directly in Program Files: no vendor folder
            return (pf, rest[..slash]);
        }
        return null;
    }

    /// <summary>
    /// The bounded set of directories related to a service: its binary's directory, its install
    /// root (the folder under Program Files*), %ProgramData%\&lt;vendor&gt;, and any directory
    /// named in its ImagePath arguments or Parameters values. Never a bare root (Program Files,
    /// ProgramData, a drive) and never anything under %SystemRoot%.
    /// </summary>
    internal static IReadOnlyList<string> RelatedDirectories(ServiceEntry s, Env env)
    {
        var dirs = new List<string>();
        void Add(string? d)
        {
            if (string.IsNullOrWhiteSpace(d)) return;
            d = Trim(d);
            if (!Path.IsPathRooted(d) || d.Length <= 3) return;                      // drive roots
            if (IsUnder(d, env.SystemRoot)) return;
            if (env.ProgramFilesRoots.Any(r => Trim(r).Equals(d, StringComparison.OrdinalIgnoreCase))) return;
            if (Trim(env.ProgramData).Equals(d, StringComparison.OrdinalIgnoreCase)) return;
            if (!dirs.Contains(d, StringComparer.OrdinalIgnoreCase)) dirs.Add(d);
        }

        Add(Path.GetDirectoryName(s.BinaryPath));
        if (VendorOf(s.BinaryPath, env) is (string root, string vendor))
        {
            Add(Path.Combine(root, vendor));
            if (!string.IsNullOrEmpty(env.ProgramData)) Add(Path.Combine(env.ProgramData, vendor));
        }

        foreach (var token in PathTokens(s.ImagePath).Concat(s.ParameterValues.SelectMany(PathTokens)))
        {
            if (Directory.Exists(token)) Add(token);
            else if (File.Exists(token)) Add(Path.GetDirectoryName(token));
        }
        return dirs;
    }

    /// <summary>Rooted paths named in a command line or registry value (quoted or bare, after '=' too).</summary>
    internal static IEnumerable<string> PathTokens(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) yield break;
        string expanded = Environment.ExpandEnvironmentVariables(text);
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(expanded,
                     "\"([A-Za-z]:\\\\[^\"]*)\"|([A-Za-z]:\\\\[^\\s\";]*)"))
        {
            string p = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            p = p.Trim().TrimEnd(',', '.');
            if (p.Length > 3 && p.IndexOfAny(Path.GetInvalidPathChars()) < 0) yield return p;
        }
    }

    private static IEnumerable<string> EnumerateExes(string dir, int maxDepth)
    {
        var queue = new Queue<(string dir, int depth)>();
        queue.Enqueue((dir, 0));
        while (queue.Count > 0)
        {
            var (d, depth) = queue.Dequeue();
            string[] files, subs;
            try { files = Directory.GetFiles(d, "*.exe"); } catch { continue; }
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);
            foreach (var f in files) yield return f;
            if (depth >= maxDepth) continue;
            try { subs = Directory.GetDirectories(d); } catch { continue; }
            Array.Sort(subs, StringComparer.OrdinalIgnoreCase);
            foreach (var sd in subs)
            {
                // Do not follow junctions/symlinks out of the bounded tree.
                try { if (new DirectoryInfo(sd).Attributes.HasFlag(FileAttributes.ReparsePoint)) continue; } catch { continue; }
                queue.Enqueue((sd, depth + 1));
            }
        }
    }

    /// <summary>
    /// Companion executables (depth ≤ <paramref name="maxDepth"/>, at most
    /// <paramref name="maxExesPerService"/> EXEs enumerated per service) whose directory a
    /// standard user can write to, for each non-guarded service running as LocalSystem,
    /// LocalService or NetworkService.
    /// </summary>
    internal static List<Companion> Find(IEnumerable<ServiceEntry> services, Env env, int maxDepth = 3,
        int maxExesPerService = 200, List<Examined>? report = null)
    {
var found = new List<Companion>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Hard ceiling on names looked at per service, so "over the cap" can be reported without unbounded walking.
        int ceiling = Math.Max(maxExesPerService, 0) * 10 + 10;
        void Note(Examined e)
        {
            report?.Add(e);
            ScanLogger.Debug(e.ExePath.Length > 0
                ? $"Companion examine: {e.ExePath} (service {e.Service}): {(e.Kept ? "kept" : "rejected")}: {e.Reason}"
                : $"Companion examine: service {e.Service} skipped: {e.Reason}");
        }
        foreach (var s in services)
        {
            if (NormalizeServiceAccount(s.Account) is not string account) continue;   // not a service account: not examined
            if (string.IsNullOrEmpty(s.BinaryPath) || IsUnder(s.BinaryPath, env.SystemRoot)) continue;
            var (guarded, why) = env.Guard(s.Name);
            if (guarded) { Note(new Examined("", s.Name, false, $"guarded service ({why}); its directories are not examined")); continue; }

            var exes = new List<string>();
            var exeSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dir in RelatedDirectories(s, env))
            {
                foreach (var exe in EnumerateExes(dir, maxDepth))
                {
                    if (exes.Count >= ceiling) break;
                    if (exeSet.Add(exe)) exes.Add(exe);
                }
                if (exes.Count >= ceiling) break;
            }

            var writableCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            int considered = 0;
            foreach (var exe in exes)
            {
                if (exe.Equals(s.BinaryPath, StringComparison.OrdinalIgnoreCase))
                { Note(new Examined(exe, s.Name, false, "the service binary itself (analysed as the service)")); continue; }
                if (++considered > maxExesPerService)
                { Note(new Examined(exe, s.Name, false, $"over the per-service cap ({maxExesPerService} executables)")); continue; }
                string? dir = Path.GetDirectoryName(exe);
                if (dir == null) continue;
                if (!IsPe(exe)) { Note(new Examined(exe, s.Name, false, "not a PE (no MZ header)")); continue; }
                if (!writableCache.TryGetValue(dir, out bool w))
                    writableCache[dir] = w = SafeWritable(env, dir, account);
                if (!w) { Note(new Examined(exe, s.Name, false, $"directory not writable by a standard user ({dir})")); continue; }
                if (!seen.Add(s.Name + "|" + exe)) continue;
                string reason = $"in {dir}, a directory related to service {s.Name} that a standard user can write to";
                Note(new Examined(exe, s.Name, true, reason));
                found.Add(new Companion(exe, s.Name, s.Account, reason));
            }
        }
        return found;
    }

    private static bool IsPe(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return fs.ReadByte() == 'M' && fs.ReadByte() == 'Z';
        }
        catch { return false; }
    }
    private static bool SafeWritable(Env env, string dir, string account)
    {
        try { return env.IsDirWritable(dir, account); } catch { return false; }
    }

    /// <summary>The execution context a companion is analysed under: the parent's trigger and identity.</summary>
    internal static DiscoveryContext ToContext(Companion c, string startType) => new()
    {
        BinaryPath = c.ExePath,
        TriggerType = TriggerType.Service,
        TriggerIdentifier = c.Service,
        DisplayName = $"{Path.GetFileName(c.ExePath)} [companion of {c.Service}]",
        RunAsAccount = NormalizeServiceAccount(c.Account) ?? c.Account,
        StartType = startType,
        IsAutoStart = startType is "AUTO_START" or "BOOT_START" or "SYSTEM_START",
        IsCompanion = true,
    };

    internal static string Note(string service) => $"possible child of {service}; not observed running";

    /// <summary>Service entries for the service contexts static discovery found (registry read only).</summary>
    internal static List<ServiceEntry> FromServiceContexts(IEnumerable<DiscoveryContext> contexts)
    {
        var list = new List<ServiceEntry>();
        foreach (var c in contexts.Where(c => c.TriggerType == TriggerType.Service && !c.IsSvchostService && !c.IsCompanion)
                     .GroupBy(c => c.TriggerIdentifier, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
        {
            string? imagePath = null;
            var values = new List<string>();
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{c.TriggerIdentifier}");
                imagePath = k?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                using var p = k?.OpenSubKey("Parameters");
                if (p != null)
                    foreach (var n in p.GetValueNames().Take(100))
                        switch (p.GetValue(n))
                        {
                            case string sv: values.Add(sv); break;
                            case string[] mv: values.AddRange(mv.Take(20)); break;
                        }
            }
            catch { }
            list.Add(new ServiceEntry(c.TriggerIdentifier, c.BinaryPath, c.RunAsAccount, imagePath, values, c.StartType));
        }
        return list;
    }
}
