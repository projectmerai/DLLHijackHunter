namespace DLLHijackHunter.Safety;

public enum SvcState { Unknown, NotFound, Stopped, StartPending, StopPending, Running, ContinuePending, PausePending, Paused }

public sealed record SvcStatus(SvcState State, int Pid = 0, string StartType = "")
{
    public bool IsPending => State is SvcState.StartPending or SvcState.StopPending
        or SvcState.ContinuePending or SvcState.PausePending;
}

/// <summary>Service Control Manager access used by <see cref="ServiceControl"/> (replaceable in unit tests).</summary>
public interface IScm
{
    SvcStatus Query(string name);
    /// <summary>Send "stop" or "start" (sc.exe). Returns when sc.exe returns or times out.</summary>
    Task<(ServiceActionOutcome outcome, string output)> SendAsync(string verb, string name, int timeoutMs);
    Task Delay(TimeSpan t);
    /// <summary>
    /// F6: null when the tool can open the SCM and the service with SERVICE_START | SERVICE_STOP (it could stop the
    /// service again after starting it); otherwise the error. Default: allowed (fakes without the check).
    /// </summary>
    string? CheckStartStopAccess(string name) => null;
    /// <summary>F6: dwControlsAccepted of the service as it is now, or null when unknown.</summary>
    int? ControlsAccepted(string name) => null;
}

/// <summary>Real SCM: status straight from the SCM (QueryServiceStatusEx), commands through sc.exe.</summary>
public sealed class RealScm : IScm
{
    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? db, uint access);
    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr svc, int level, byte[] buf, int size, out int needed);
    [System.Runtime.InteropServices.DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr h);

    private const uint SC_MANAGER_CONNECT = 0x0001, SERVICE_QUERY_STATUS = 0x0004;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;

    public SvcStatus Query(string name)
    {
        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return new SvcStatus(SvcState.Unknown);
        try
        {
            IntPtr svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero)
                return new SvcStatus(System.Runtime.InteropServices.Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST
                    ? SvcState.NotFound : SvcState.Unknown);
            try
            {
                var buf = new byte[36];   // SERVICE_STATUS_PROCESS
                if (!QueryServiceStatusEx(svc, 0, buf, buf.Length, out _)) return new SvcStatus(SvcState.Unknown);
                int cur = BitConverter.ToInt32(buf, 4), pid = BitConverter.ToInt32(buf, 28);
                var state = cur switch
                {
                    1 => SvcState.Stopped, 2 => SvcState.StartPending, 3 => SvcState.StopPending, 4 => SvcState.Running,
                    5 => SvcState.ContinuePending, 6 => SvcState.PausePending, 7 => SvcState.Paused, _ => SvcState.Unknown
                };
                return new SvcStatus(state, pid, StartTypeOf(name));
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    private static string StartTypeOf(string name)
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}");
            return (k?.GetValue("Start") as int?) switch
            { 0 => "BOOT_START", 1 => "SYSTEM_START", 2 => "AUTO_START", 3 => "DEMAND_START", 4 => "DISABLED", _ => "" };
        }
        catch { return ""; }
    }
    public Task<(ServiceActionOutcome outcome, string output)> SendAsync(string verb, string name, int timeoutMs) =>
        ServiceControl.RunScAsync($"{verb} \"{name}\"", timeoutMs);

    public Task Delay(TimeSpan t) => Task.Delay(t);

    private const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020;

    /// <summary>
    /// F6: open the SCM (SC_MANAGER_CONNECT, what sc.exe uses for start and stop) and the service with
    /// SERVICE_START | SERVICE_STOP. gpsvc on Windows 11 (TIER 5 VM run): the ETW phase started it, and every later
    /// "sc stop" failed with OpenService error 5, so it could not be put back in its snapshot state.
    /// </summary>
    public string? CheckStartStopAccess(string name)
    {
        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return $"OpenSCManager failed {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}";
        try
        {
            IntPtr svc = OpenServiceW(scm, name, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero)
            {
                int err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                return $"OpenService(SERVICE_START | SERVICE_STOP) failed {err}" + (err == 5 ? ": access denied" : "");
            }
            CloseServiceHandle(svc);
            return null;
        }
        finally { CloseServiceHandle(scm); }
    }

    public int? ControlsAccepted(string name)
    {
        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return null;
        try
        {
            IntPtr svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero) return null;
            try
            {
                var buf = new byte[36];   // SERVICE_STATUS_PROCESS: dwControlsAccepted at offset 8
                return QueryServiceStatusEx(svc, 0, buf, buf.Length, out _) ? BitConverter.ToInt32(buf, 8) : null;
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }
}

/// <summary>
/// Per-scan snapshot of every service the tool may touch, taken once, before anything is
/// changed, plus which services the tool actually sent a stop or a start to.
/// </summary>
public sealed class ServiceStateTracker
{
    private readonly object _lock = new();
    private readonly Dictionary<string, SvcStatus> _snapshot = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _stopped = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _started = new(StringComparer.OrdinalIgnoreCase);

    public SvcStatus? Snapshot(string name) { lock (_lock) return _snapshot.TryGetValue(name, out var s) ? s : null; }
    internal void Record(string name, SvcStatus s) { lock (_lock) _snapshot.TryAdd(name, s); }
    internal void MarkStop(string name) { lock (_lock) _stopped.Add(name); }
    internal void MarkStart(string name) { lock (_lock) _started.Add(name); }
    internal bool WasStopSent(string name) { lock (_lock) return _stopped.Contains(name); }
    internal bool WasStartSent(string name) { lock (_lock) return _started.Contains(name); }
    // F6: started by the tool, RUNNING (a stable state) without SERVICE_ACCEPT_STOP: provisionally not restorable. No stop
    // is attempted; the end-of-scan check decides (back in its snapshot state = no residue; otherwise service-not-restorable).
    internal sealed record Provisional(string ActorId, Models.HijackCandidate? Candidate, string Why, DateTime StartRequestedUtc);
    private readonly Dictionary<string, Provisional> _notRestorable = new(StringComparer.OrdinalIgnoreCase);
    internal void MarkNotRestorable(string name, Provisional p) { lock (_lock) _notRestorable.TryAdd(name, p); }
    private readonly HashSet<string> _finalNotRestorable = new(StringComparer.OrdinalIgnoreCase);
    internal bool IsNotRestorable(string name) { lock (_lock) return _notRestorable.ContainsKey(name) || _finalNotRestorable.Contains(name); }
    internal IReadOnlyList<KeyValuePair<string, Provisional>> ProvisionalNotRestorable { get { lock (_lock) return _notRestorable.ToList(); } }
    /// <summary>Back in its snapshot state on its own: restorable again, nothing to report.</summary>
    internal void ClearNotRestorable(string name) { lock (_lock) _notRestorable.Remove(name); }
    /// <summary>Reported as service-not-restorable residue: never restored and never reported again.</summary>
    internal void MarkFinalNotRestorable(string name) { lock (_lock) { _notRestorable.Remove(name); _finalNotRestorable.Add(name); } }
    public IReadOnlyList<string> Touched { get { lock (_lock) return _stopped.Union(_started, StringComparer.OrdinalIgnoreCase).ToList(); } }
    public IReadOnlyDictionary<string, SvcStatus> All { get { lock (_lock) return new Dictionary<string, SvcStatus>(_snapshot, StringComparer.OrdinalIgnoreCase); } }
}
