using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace DLLHijackHunter.Native;

/// <summary>
/// Attacker-relative writability checks.
///
/// The question answered here is NOT "can the process running this tool write here?"
/// — that is meaningless when the tool runs elevated, because an Administrator token
/// can write to System32 / Program Files and every directory would look hijackable.
/// Instead it answers "can an UNPRIVILEGED principal write here?".
///
/// Effective rights are computed against the well-known low-privilege SIDs
/// Users (S-1-5-32-545), Authenticated Users (S-1-5-11), Everyone (S-1-1-0) and INTERACTIVE (S-1-5-4)
/// using GetNamedSecurityInfo + GetEffectiveRightsFromAcl + BuildTrusteeWithSid,
/// completely independent of the current process token's group membership.
///
/// A candidate's known (non-privileged) service RunAsAccount can be added as an
/// extra principal; privileged accounts (SYSTEM / Administrators / High-Integrity)
/// are deliberately excluded so they cannot re-introduce the false positives this
/// check exists to remove.
/// </summary>
public static class AclChecker
{
    // Directory access rights that let an attacker drop or replace a DLL.
    private const uint FILE_ADD_FILE         = 0x0002; // create a new file in the directory
    private const uint FILE_ADD_SUBDIRECTORY = 0x0004; // create a subdirectory (e.g. <bin>.local)
    private const uint GENERIC_WRITE         = 0x40000000;
    private const uint GENERIC_ALL           = 0x10000000;
    private const uint WRITE_MASK =
        FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE | GENERIC_ALL;

    private const uint ERROR_SUCCESS = 0;

    // The unprivileged principals an attacker is assumed to control.
    private static readonly SecurityIdentifier[] StandardUserSids =
    {
        new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),      // S-1-5-32-545
        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), // S-1-5-11
        new SecurityIdentifier(WellKnownSidType.WorldSid, null),             // S-1-1-0 (Everyone)
        new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),       // S-1-5-4 (INTERACTIVE — every console/RDP logon)
    };

    // Directory ACLs do not change during a scan, and the same directories
    // (System32, PATH entries, app dirs) get probed thousands of times. Memoize
    // by path + optional extra account so the effective-rights call runs once each.
    private static readonly ConcurrentDictionary<string, bool> _cache = new();

    /// <summary>
    /// True if an unprivileged attacker could create or replace a file in this directory.
    /// Optionally also evaluates a (non-privileged) service RunAsAccount.
    /// </summary>
    public static bool IsDirectoryWritableByStandardUser(string path, string? alsoEvaluateAccount = null)
    {
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            return false;

        string key = path.ToLowerInvariant() + "|" + (alsoEvaluateAccount ?? "");
        if (_cache.TryGetValue(key, out bool cached))
            return cached;

        bool result = EvaluateWritable(path, BuildPrincipals(alsoEvaluateAccount));
        _cache[key] = result;
        return result;
    }

    /// <summary>
    /// Check whether an unprivileged principal could create a directory at the given path.
    /// </summary>
    public static bool CanCreateDirectory(string path, string? alsoEvaluateAccount = null)
    {
        if (string.IsNullOrEmpty(path)) return false;

        string? parent = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(parent)) return false;

        return IsDirectoryWritableByStandardUser(parent, alsoEvaluateAccount);
    }

    /// <summary>
    /// Check whether an unprivileged principal could write the given file path.
    /// </summary>
    public static bool CanWriteFile(string filePath, string? alsoEvaluateAccount = null)
    {
        string? dir = Path.GetDirectoryName(filePath);
        if (string.IsNullOrEmpty(dir)) return false;

        if (!Directory.Exists(dir))
            return CanCreateDirectory(dir, alsoEvaluateAccount);

        return IsDirectoryWritableByStandardUser(dir, alsoEvaluateAccount);
    }

    private static List<SecurityIdentifier> BuildPrincipals(string? alsoEvaluateAccount)
    {
        var principals = new List<SecurityIdentifier>(StandardUserSids);

        var extra = TryResolveServiceAccount(alsoEvaluateAccount);
        if (extra != null) principals.Add(extra);

        return principals;
    }

    /// <summary>
    /// Resolve a candidate's RunAsAccount to an additional principal, but ONLY for
    /// the well-known service accounts that are strictly below Administrator.
    ///
    /// We deliberately do NOT resolve arbitrary account names. An interactive
    /// RunKey/Startup account (e.g. "DOMAIN\alice") or a custom account may itself
    /// be a member of Administrators, and GetEffectiveRightsFromAcl would then report
    /// System32/Program Files as writable — re-introducing the exact privilege-relative
    /// false positive this class exists to remove. SYSTEM is excluded for the same reason.
    /// Local Service / Network Service cannot write protected system directories, so
    /// they are safe to include and may surface a service's own writable data directory.
    /// </summary>
    private static SecurityIdentifier? TryResolveServiceAccount(string? account)
    {
        if (string.IsNullOrWhiteSpace(account)) return null;

        return account.ToUpperInvariant() switch
        {
            "NT AUTHORITY\\LOCAL SERVICE"   => new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null),
            "NT AUTHORITY\\NETWORK SERVICE" => new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
            _ => null
        };
    }

    private static bool EvaluateWritable(string path, List<SecurityIdentifier> principals)
    {
        IntPtr pSecurityDescriptor = IntPtr.Zero;
        try
        {
            uint err = NativeMethods.GetNamedSecurityInfoW(
                path,
                NativeMethods.SE_FILE_OBJECT,
                NativeMethods.DACL_SECURITY_INFORMATION,
                out _, out _, out IntPtr pDacl, out _, out pSecurityDescriptor);

            if (err != ERROR_SUCCESS)
                return false;

            // A NULL DACL grants everyone full control.
            if (pDacl == IntPtr.Zero)
                return true;

            foreach (var sid in principals)
            {
                if (TrusteeHasWrite(pDacl, sid))
                    return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (pSecurityDescriptor != IntPtr.Zero)
                NativeMethods.LocalFree(pSecurityDescriptor);
        }
    }

    private static bool TrusteeHasWrite(IntPtr pDacl, SecurityIdentifier sid)
    {
        IntPtr pSid = IntPtr.Zero;
        try
        {
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            pSid = Marshal.AllocHGlobal(sidBytes.Length);
            Marshal.Copy(sidBytes, 0, pSid, sidBytes.Length);

            var trustee = new NativeMethods.TRUSTEE();
            NativeMethods.BuildTrusteeWithSidW(ref trustee, pSid);

            uint err = NativeMethods.GetEffectiveRightsFromAclW(pDacl, ref trustee, out uint accessRights);
            if (err != ERROR_SUCCESS)
                return false;

            return (accessRights & WRITE_MASK) != 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            // pSid is only referenced by the trustee during the synchronous
            // GetEffectiveRightsFromAcl call above, so it is safe to free here.
            if (pSid != IntPtr.Zero) Marshal.FreeHGlobal(pSid);
        }
    }
}
