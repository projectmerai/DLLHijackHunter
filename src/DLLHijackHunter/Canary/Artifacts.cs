using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DLLHijackHunter.Models;

namespace DLLHijackHunter.Canary;

/// <summary>One file the tool placed (or is about to place) on the machine.</summary>
public sealed class ArtifactEntry
{
    public string Path { get; set; } = "";
    public ArtifactRole Role { get; set; }
    // SHA-256 (upper-case hex) of the content the tool wrote. Null for a confirm file, which the
    // canary itself writes; those are only ever deleted inside the tool's own folder.
    public string? Sha256 { get; set; }
    public string ScanId { get; set; } = "";
    public string? CandidateId { get; set; }
    // Backup role: the path the backup restores to.
    public string? RestoreTo { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// %ProgramData%\DLLHijackHunter\artifacts.json: every file the tool places, recorded BEFORE it
/// is placed and removed only after the file is verified gone (or the original verified restored).
/// Each write goes to a temp file that then replaces the manifest, so a crash never leaves a
/// truncated manifest. In production the file must be owned by SYSTEM/Administrators and not
/// writable by anyone else, or it is ignored: its entries drive file deletion as SYSTEM.
/// </summary>
public sealed class ArtifactManifest
{
    private readonly object _lock = new();
    private readonly bool _requireTrusted;
    private List<ArtifactEntry> _entries = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string DefaultPath => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DLLHijackHunter", "artifacts.json");

    /// <summary>The manifest of the running scan (null outside a scan, e.g. in unit tests).</summary>
    public static ArtifactManifest? Current { get; set; }

    public ArtifactManifest(string path, bool requireTrustedFile = true)
    {
        FilePath = path;
        _requireTrusted = requireTrustedFile;
        Load();
    }

    public string FilePath { get; }
    public bool Trusted { get; private set; } = true;
    public string? LoadProblem { get; private set; }

    public IReadOnlyList<ArtifactEntry> Entries
    {
        get { lock (_lock) return _entries.ToList(); }
    }

    public ArtifactEntry? Find(string path)
    {
        lock (_lock)
            return _entries.FirstOrDefault(e => PathsEqual(e.Path, path));
    }

    /// <summary>Record an artifact (replacing an entry for the same path). Throws if it cannot be persisted.</summary>
    public void Add(ArtifactEntry entry)
    {
        lock (_lock)
        {
            var next = _entries.Where(e => !PathsEqual(e.Path, entry.Path)).ToList();
            next.Add(entry);
            Save(next);
            _entries = next;
        }
    }

    /// <summary>Drop the entry for a path. Call only once the file is verified gone / restored.</summary>
    public bool Remove(string path)
    {
        lock (_lock)
        {
            var next = _entries.Where(e => !PathsEqual(e.Path, path)).ToList();
            if (next.Count == _entries.Count) return false;
            Save(next);
            _entries = next;
            return true;
        }
    }

    private void Load()
    {
        lock (_lock)
        {
            _entries = new();
            if (!File.Exists(FilePath)) return;
            if (_requireTrusted && !ManifestTrust.IsTrustedFile(FilePath, out string why))
            {
                Trusted = false;
                LoadProblem = $"artifact manifest ignored: {why}";
                return;
            }
            try
            {
                var doc = JsonSerializer.Deserialize<ManifestDocument>(File.ReadAllText(FilePath), JsonOptions);
                _entries = doc?.Entries ?? new();
            }
            catch (Exception ex)
            {
                LoadProblem = $"artifact manifest unreadable: {ex.Message}";
            }
        }
    }

    private void Save(List<ArtifactEntry> entries)
    {
        string dir = System.IO.Path.GetDirectoryName(FilePath)!;
        Directory.CreateDirectory(dir);
        string tmp = $"{FilePath}.{Guid.NewGuid():N}.tmp";
        byte[] bytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new ManifestDocument { Entries = entries }, JsonOptions));
        try
        {
            using (var fs = _requireTrusted
                       ? new FileInfo(tmp).Create(FileMode.CreateNew, FileSystemRights.FullControl,
                           FileShare.None, 4096, FileOptions.None, ManifestTrust.ProtectedFileSecurity())
                       : new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(bytes);
                fs.Flush(flushToDisk: true);
            }
            File.Move(tmp, FilePath, overwrite: true);   // MoveFileEx(REPLACE_EXISTING): atomic on one volume
            Trusted = true;
            LoadProblem = null;
        }
        catch
        {
            try { File.Delete(tmp); } catch { }
            throw;
        }
    }

    internal static bool PathsEqual(string a, string b)
    {
        try { return string.Equals(System.IO.Path.GetFullPath(a), System.IO.Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
        catch { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
    }

    private sealed class ManifestDocument
    {
        public int Version { get; set; } = 1;
        public List<ArtifactEntry> Entries { get; set; } = new();
    }
}

/// <summary>Who may write the manifest: only SYSTEM, Administrators and TrustedInstaller.</summary>
internal static class ManifestTrust
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private const FileSystemRights WriteLike = FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership |
        FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;

    private static bool IsTrustedSid(IdentityReference? id) =>
        id is SecurityIdentifier sid && (sid == System || sid == Admins || sid.Value == TrustedInstaller);

    public static bool IsTrustedFile(string path, out string why)
    {
        why = "";
        try
        {
            var sec = new FileInfo(path).GetAccessControl();
            var owner = sec.GetOwner(typeof(SecurityIdentifier));
            if (!IsTrustedSid(owner))
            {
                why = $"owner {owner} is not SYSTEM or Administrators";
                return false;
            }
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & WriteLike) != 0 &&
                    !IsTrustedSid(rule.IdentityReference))
                {
                    why = $"{rule.IdentityReference} can modify it";
                    return false;
                }
            }
            return true;
        }
        catch (Exception ex)
        {
            why = ex.Message;
            return false;
        }
    }

    /// <summary>Protected DACL: SYSTEM and Administrators full control, Users read.</summary>
    public static FileSecurity ProtectedFileSecurity()
    {
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        sec.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Read, AccessControlType.Allow));
        try { sec.SetOwner(Admins); } catch { }
        return sec;
    }
}

/// <summary>File operations the artifact code needs; abstracted so unit tests can stub reboot-time scheduling.</summary>
public interface IFileOps
{
    bool Exists(string path);
    void Delete(string path);
    void Move(string source, string dest, bool overwrite);
    void Copy(string source, string dest, bool overwrite);
    string? Sha256(string path);
    bool ScheduleDeleteOnReboot(string path);
    bool ScheduleMoveOnReboot(string source, string dest);
    string? FindLockHolders(string path);
}

public class RealFileOps : IFileOps
{
    public virtual bool Exists(string path) => File.Exists(path);
    public virtual void Delete(string path) => File.Delete(path);
    public virtual void Move(string source, string dest, bool overwrite) => File.Move(source, dest, overwrite);
    public virtual void Copy(string source, string dest, bool overwrite) => File.Copy(source, dest, overwrite);

    public virtual string? Sha256(string path) => ArtifactHash.OfFile(path);

    private const int MOVEFILE_REPLACE_EXISTING = 0x1;
    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);

    public virtual bool ScheduleDeleteOnReboot(string path) =>
        MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT);

    public virtual bool ScheduleMoveOnReboot(string source, string dest) =>
        MoveFileEx(source, dest, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);

    public virtual string? FindLockHolders(string path) => RestartManager.DescribeHolders(path);
}

public static class ArtifactHash
{
    public static string Of(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    public static string? OfFile(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(fs));
        }
        catch { return null; }
    }
}

/// <summary>Restart Manager: which processes hold a file open.</summary>
internal static class RestartManager
{
    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, RM_UNIQUE_PROCESS[]? rgApplications, uint nServices, string[]? rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[]? rgAffectedApps, ref uint lpdwRebootReasons);

    private const int ERROR_MORE_DATA = 234;

    /// <summary>"name (PID n)[, ...]", or null when nothing holds it / RM is unavailable.</summary>
    public static string? DescribeHolders(string path)
    {
        try
        {
            if (RmStartSession(out uint session, 0, new StringBuilder(33)) != 0) return null;
            try
            {
                if (RmRegisterResources(session, 1, new[] { path }, 0, null, 0, null) != 0) return null;
                uint needed, count = 0, reasons = 0;
                int rc = RmGetList(session, out needed, ref count, null, ref reasons);
                if (rc == 0) return null;               // no holders
                if (rc != ERROR_MORE_DATA) return null;
                var infos = new RM_PROCESS_INFO[needed];
                count = needed;
                if (RmGetList(session, out needed, ref count, infos, ref reasons) != 0) return null;
                var names = infos.Take((int)count).Select(i =>
                {
                    string name = i.strAppName;
                    try
                    {
                        using var p = System.Diagnostics.Process.GetProcessById(i.Process.dwProcessId);
                        name = p.ProcessName + ".exe";
                    }
                    catch { }
                    if (!string.IsNullOrEmpty(i.strServiceShortName)) name += $" [service {i.strServiceShortName}]";
                    return $"{name} (PID {i.Process.dwProcessId})";
                });
                return string.Join(", ", names);
            }
            finally
            {
                RmEndSession(session);
            }
        }
        catch
        {
            return null;
        }
    }
}

public sealed class CleanupOptions
{
    public int Attempts { get; init; } = 5;
    // ~5 s in total: 0.25 + 0.5 + 1 + 1.5 + 2 s.
    public Func<int, TimeSpan> Backoff { get; init; } = attempt => attempt switch
    {
        1 => TimeSpan.FromMilliseconds(250),
        2 => TimeSpan.FromMilliseconds(500),
        3 => TimeSpan.FromMilliseconds(1000),
        4 => TimeSpan.FromMilliseconds(1500),
        _ => TimeSpan.FromMilliseconds(2000)
    };
}

/// <summary>
/// Removal of a placed artifact: delete; on failure stop the trigger again (the caller's
/// callback honours the service guard), retry with backoff, name the holder with the Restart
/// Manager, schedule a delete at reboot, and return a residue record. Never silent.
/// </summary>
public static class ArtifactCleaner
{
    public static async Task<ResidueEntry?> RemoveAsync(string path, ArtifactRole role, string? sha256,
        string? candidateId, IFileOps fs, Func<Task>? stopTrigger, CleanupOptions? options = null,
        Action<string, string, string>? audit = null)
    {
        options ??= new CleanupOptions();
        audit ??= (_, _, _) => { };
        string? lastError = null;

        for (int attempt = 1; attempt <= Math.Max(1, options.Attempts); attempt++)
        {
            if (!fs.Exists(path))
            {
                if (attempt > 1) audit("file-deleted", path, $"ok (attempt {attempt - 1})");
                return null;
            }
            try
            {
                fs.Delete(path);
                if (!fs.Exists(path))
                {
                    audit("file-deleted", path, attempt == 1 ? "ok" : $"ok (attempt {attempt})");
                    return null;
                }
                lastError = "file still present after delete";
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
            }

            audit("file-delete-failed", path, $"attempt {attempt}: {lastError}");
            if (attempt == 1 && stopTrigger != null)
            {
                try { await stopTrigger(); } catch { }
            }
            if (attempt < options.Attempts)
                await Task.Delay(options.Backoff(attempt));
        }

        string? holder = fs.FindLockHolders(path);
        if (holder != null) audit("file-lock-holder", path, holder);
        bool scheduled = false;
        try { scheduled = fs.ScheduleDeleteOnReboot(path); } catch { }
        audit("file-delete-delayed", path, scheduled ? "scheduled for next reboot" : "could not schedule");

        return new ResidueEntry
        {
            Path = path,
            Role = role,
            Sha256 = sha256 ?? fs.Sha256(path),
            Holder = holder,
            DelayedDeleteScheduled = scheduled,
            CandidateId = candidateId,
            Reason = $"could not delete after {options.Attempts} attempts: {lastError}"
        };
    }

    /// <summary>Move a backup back over its target (which must already be free of the canary).</summary>
    public static async Task<ResidueEntry?> RestoreAsync(string backupPath, string targetPath, string? sha256,
        string? candidateId, IFileOps fs, Func<Task>? stopTrigger, CleanupOptions? options = null,
        Action<string, string, string>? audit = null)
    {
        options ??= new CleanupOptions();
        audit ??= (_, _, _) => { };
        string? lastError = null;

        for (int attempt = 1; attempt <= Math.Max(1, options.Attempts); attempt++)
        {
            if (!fs.Exists(backupPath)) return null;
            try
            {
                fs.Move(backupPath, targetPath, overwrite: true);
                audit("file-restored", targetPath, attempt == 1 ? "ok" : $"ok (attempt {attempt})");
                return null;
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
            }
            audit("file-restore-failed", targetPath, $"attempt {attempt}: {lastError}");
            if (attempt == 1 && stopTrigger != null)
            {
                try { await stopTrigger(); } catch { }
            }
            if (attempt < options.Attempts)
                await Task.Delay(options.Backoff(attempt));
        }

        string? holder = fs.FindLockHolders(targetPath);
        if (holder != null) audit("file-lock-holder", targetPath, holder);
        bool scheduled = false;
        try { scheduled = fs.ScheduleMoveOnReboot(backupPath, targetPath); } catch { }
        audit("file-restore-delayed", targetPath, scheduled ? "scheduled for next reboot" : "could not schedule");

        return new ResidueEntry
        {
            Path = backupPath,
            Role = ArtifactRole.Backup,
            Sha256 = sha256 ?? fs.Sha256(backupPath),
            Holder = holder,
            DelayedDeleteScheduled = scheduled,
            CandidateId = candidateId,
            Reason = $"could not restore the original to {targetPath}: {lastError}"
        };
    }
}

/// <summary>
/// Startup sweep: process manifest entries a previous run left behind. Deletes a leftover only
/// when its hash matches what the tool wrote (never a file the tool didn't write), restores
/// recorded backups, and reports everything it did or left alone.
/// </summary>
public static class ArtifactSweeper
{
    public static List<SweepItem> Sweep(ArtifactManifest manifest, IFileOps fs, List<ResidueEntry> residue)
    {
        var items = new List<SweepItem>();
        if (!manifest.Trusted) return items;

        // Placed files first (canary, sidecar, confirm), then backups, so a restore finds its
        // target free.
        var ordered = manifest.Entries.OrderBy(e => e.Role == ArtifactRole.Backup ? 1 : 0).ToList();
        foreach (var e in ordered)
        {
            var item = new SweepItem { Path = e.Path, Role = e.Role, ScanId = e.ScanId };
            items.Add(item);
            try
            {
                if (e.Role == ArtifactRole.Backup) SweepBackup(e, item, manifest, fs, residue);
                else SweepPlaced(e, item, manifest, fs, residue);
            }
            catch (Exception ex)
            {
                item.Outcome = "DeleteFailed";
                item.Detail = ex.Message;
            }
        }
        return items;
    }

    private static void SweepPlaced(ArtifactEntry e, SweepItem item, ArtifactManifest manifest, IFileOps fs,
        List<ResidueEntry> residue)
    {
        if (!fs.Exists(e.Path))
        {
            item.Outcome = "AlreadyGone";
            manifest.Remove(e.Path);
            return;
        }

        string? current = fs.Sha256(e.Path);
        bool ours = e.Sha256 == null
            ? e.Role == ArtifactRole.Confirm && ArtifactPaths.IsUnderToolFolder(e.Path)
            : string.Equals(current, e.Sha256, StringComparison.OrdinalIgnoreCase);
        if (!ours)
        {
            item.Outcome = "HashMismatchLeftAlone";
            item.Detail = $"current SHA-256 {current ?? "unreadable"} != recorded {e.Sha256 ?? "(none)"}; not deleted";
            manifest.Remove(e.Path);   // the file is no longer ours; report once
            return;
        }

        try
        {
            fs.Delete(e.Path);
        }
        catch (Exception ex)
        {
            item.Detail = ex.Message;
        }
        if (!fs.Exists(e.Path))
        {
            item.Outcome = "Deleted";
            manifest.Remove(e.Path);
            return;
        }

        bool scheduled = false;
        try { scheduled = fs.ScheduleDeleteOnReboot(e.Path); } catch { }
        item.Outcome = "DeleteFailed";
        residue.Add(new ResidueEntry
        {
            Path = e.Path,
            Role = e.Role,
            Sha256 = current,
            Holder = fs.FindLockHolders(e.Path),
            DelayedDeleteScheduled = scheduled,
            CandidateId = e.CandidateId,
            Reason = $"left by scan {e.ScanId}; startup sweep could not delete it: {item.Detail}"
        });
    }

    private static void SweepBackup(ArtifactEntry e, SweepItem item, ArtifactManifest manifest, IFileOps fs,
        List<ResidueEntry> residue)
    {
        if (!fs.Exists(e.Path))
        {
            item.Outcome = "AlreadyGone";
            manifest.Remove(e.Path);
            return;
        }
        if (!string.Equals(fs.Sha256(e.Path), e.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            item.Outcome = "HashMismatchLeftAlone";
            item.Detail = "backup content changed since it was taken; not restored";
            manifest.Remove(e.Path);
            return;
        }
        if (string.IsNullOrEmpty(e.RestoreTo) || fs.Exists(e.RestoreTo))
        {
            // Something that is not a recorded artifact occupies the original's place: do not
            // overwrite it. Keep the entry so the next run reports it again.
            item.Outcome = "RestoreTargetOccupied";
            item.Detail = $"{e.RestoreTo} exists and is not a recorded artifact; backup kept at {e.Path}";
            residue.Add(new ResidueEntry
            {
                Path = e.Path, Role = ArtifactRole.Backup, Sha256 = e.Sha256, CandidateId = e.CandidateId,
                Reason = item.Detail
            });
            return;
        }
        try
        {
            fs.Move(e.Path, e.RestoreTo, overwrite: false);
            item.Outcome = "Restored";
            item.Detail = $"restored to {e.RestoreTo}";
            manifest.Remove(e.Path);
        }
        catch (Exception ex)
        {
            item.Outcome = "RestoreFailed";
            item.Detail = ex.Message;
            residue.Add(new ResidueEntry
            {
                Path = e.Path, Role = ArtifactRole.Backup, Sha256 = e.Sha256, CandidateId = e.CandidateId,
                Holder = fs.FindLockHolders(e.RestoreTo), Reason = $"startup sweep could not restore: {ex.Message}"
            });
        }
    }
}

/// <summary>The canary marker: a fixed ASCII string every canary build the tool deploys carries.</summary>
public static class CanaryMarker
{
    /// <summary>In the precompiled canaries (Resources/canary_src.c), hence in probes and proxies too.</summary>
    public const string CanaryString = "[DllHijackHunter] precompiled canary fired";

    /// <summary>Added by RuntimeProxyBuilder to every runtime-synthesised proxy.</summary>
    public const string ProxyString = "DLLHijackHunter-runtime-proxy-canary";

    private static readonly byte[] CanaryBytes = Encoding.ASCII.GetBytes(CanaryString);
    private static readonly byte[] ProxyBytes = Encoding.ASCII.GetBytes(ProxyString);

    public static bool HasMarker(ReadOnlySpan<byte> bytes) =>
        bytes.IndexOf(CanaryBytes) >= 0 || bytes.IndexOf(ProxyBytes) >= 0;

    public static bool FileHasMarker(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length > 16 * 1024 * 1024) return false;   // canaries are tiny
            var buf = new byte[fs.Length];
            fs.ReadExactly(buf);
            return HasMarker(buf);
        }
        catch { return false; }
    }
}

/// <summary>Paths that are DLLHijackHunter's own artifacts and must never become a candidate.</summary>
public static class ArtifactPaths
{
    public static string ToolFolder => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DLLHijackHunter");

    public static bool IsUnderToolFolder(string path)
    {
        try
        {
            return System.IO.Path.GetFullPath(path).StartsWith(ToolFolder + System.IO.Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>
    /// A sidecar name (*_hhorig.dll), a backup (*.hijackhunter.bak, *.probebak), anything under
    /// %ProgramData%\DLLHijackHunter, or a manifest entry. A manifest entry with role Canary at a
    /// deploy position is NOT excluded: that path is the victim's real hijack position.
    /// </summary>
    public static bool IsToolArtifact(string path, ArtifactManifest? manifest)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string name = System.IO.Path.GetFileName(path);
        if (name.EndsWith("_hhorig.dll", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".hijackhunter.bak", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".probebak", StringComparison.OrdinalIgnoreCase))
            return true;
        if (IsUnderToolFolder(path)) return true;
        var e = manifest?.Find(path);
        return e != null && e.Role != ArtifactRole.Canary;
    }
}

public enum DeployPathKind { Absent, Original, ToolArtifact }
