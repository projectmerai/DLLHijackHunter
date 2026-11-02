using DLLHijackHunter.Models;
using DLLHijackHunter.Native;

namespace DLLHijackHunter.Filters;

/// <summary>
/// HARD GATE: If we can't write to the hijack path, we can't exploit it.
/// Uses proper ACL checking (not file-write test which lies under UAC virtualization).
/// </summary>
public class WritabilityFilter : IHardGate
{
    public string Name => "Directory Writability (ACL)";
    private readonly bool _lpeOnly;

    // Constructor now accepts the LPE flag
    public WritabilityFilter(bool lpeOnly = false)
    {
        _lpeOnly = lpeOnly;
    }

    public List<HijackCandidate> Apply(List<HijackCandidate> candidates)
    {
        return candidates.Where(c =>
        {
            if (c.Type == HijackType.EnvPath)
            {
                c.FilterResults["Writability"] = FilterResult.Passed;
                return true;
            }

            if (c.IsSimulatedCopyAttack)
            {
                c.FilterResults["Writability"] = FilterResult.Passed;
                return true;
            }

            string targetPath = c.HijackWritablePath;
            if (string.IsNullOrEmpty(targetPath))
            {
                c.FilterResults["Writability"] = FilterResult.Failed;
                return false;
            }

            // ═══ NEW: LPE-ONLY MODE ═══
            if (_lpeOnly)
            {
                // If the path is in a default Admin-only location, kill it immediately
                if (targetPath.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase) ||
                    targetPath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase) ||
                    targetPath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase) ||
                    targetPath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
                {
                    c.FilterResults["Writability"] = FilterResult.Failed;
                    return false;
                }
            }

            bool writable;

            if (c.Type == HijackType.DotLocal)
            {
                string? dotLocalParent = Path.GetDirectoryName(Path.GetDirectoryName(targetPath));
                writable = dotLocalParent != null &&
                    AclChecker.CanCreateSubdirectory(dotLocalParent, c.RunAsAccount);
            }
            else
            {
                writable = AclChecker.CanWriteFile(targetPath, c.RunAsAccount);
            }

            c.FilterResults["Writability"] = writable ? FilterResult.Passed : FilterResult.Failed;
            return writable;
        }).ToList();
    }
}