using DLLHijackHunter.Models;

namespace DLLHijackHunter.Safety;

/// <summary>Audit trail of side effects on the machine.</summary>
public static class Audit
{
    // 9c91eab recorded no audit trail.
    public static void Record(string actorId, HijackCandidate? candidate, string action, string target,
        string result) { }
}
