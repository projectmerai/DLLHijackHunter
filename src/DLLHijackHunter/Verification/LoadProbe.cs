using System.Diagnostics;
using System.Text;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Spectre.Console;

namespace DLLHijackHunter.Verification;

/// <summary>
/// Opt-in load-order verification (<c>--verify-load</c>). For each applicable candidate it places
/// a benign probe DLL at the writable hijack position and asks the *real Windows loader* — in a
/// short-lived child process — to resolve the DLL by name. If the loader picks the writable
/// position, the search-order claim is verified; if it picks a protected path (a KnownDLL,
/// System32, or a SxS-redirected copy), the candidate is almost certainly a false positive.
///
/// Why a child process: (1) a name already loaded into the scanner would short-circuit
/// LoadLibraryEx and report a misleading path; (2) it isolates any load side effect or crash from
/// the scan. The probe runs as a standard user and needs no elevation.
///
/// Fidelity: this models the modern LOAD_LIBRARY_SEARCH ordering (writable user dir ahead of
/// System32, KnownDLLs always ahead of everything). It is only run for Phantom/SearchOrder/SideLoad
/// candidates, where that ordering faithfully represents the real search; DotLocal/EnvPath/AppInit
/// have different mechanics and are marked Skipped.
/// </summary>
public static class LoadProbe
{
    // Traditional (non-opt-in) search: SetCurrentDirectory positions the DLL in
    // the CWD slot of the classic search order, then LoadLibraryW resolves it
    // without any SEARCH_* flags — faithfully modelling how most services load.
    [System.Runtime.InteropServices.DllImport("kernel32.dll",
        SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool SetCurrentDirectory(string lpPathName);

    [System.Runtime.InteropServices.DllImport("kernel32.dll",
        SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr LoadLibraryW(string lpLibFileName);

    // SetDllDirectory inserts a directory into the classic search order immediately after
    // the application directory and BEFORE System32 — exactly where a hijacking DLL in the
    // target's own (application) directory sits relative to the system copy.
    [System.Runtime.InteropServices.DllImport("kernel32.dll",
        SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool SetDllDirectoryW(string? lpPathName);

    /// <summary>
    /// Child-process entry point for application-directory positions: models the target
    /// loading a DLL by name from its own directory under the classic (non-opt-in) search
    /// order — KnownDLLs first, then the app directory, then System32.
    /// </summary>
    internal static int RunChildAppDir(string appDir, string dllName)
    {
        try
        {
            if (!Directory.Exists(appDir) || !SetDllDirectoryW(appDir))
            {
                Console.Out.Write("NOTRESOLVED");
                return 0;
            }

            IntPtr h = LoadLibraryW(dllName);
            if (h == IntPtr.Zero)
            {
                // Report WHY the load failed (e.g. 225 = blocked by AV/Defender,
                // 577/1260 = code-integrity / application-control policy, 126 = not found).
                Console.Out.Write("NOTRESOLVED:" + System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                return 0;
            }

            var sb = new StringBuilder(1024);
            NativeMethods.GetModuleFileNameW(h, sb, 1024);
            NativeMethods.FreeLibrary(h);

            string resolved = sb.ToString();
            Console.Out.Write(string.IsNullOrEmpty(resolved) ? "NOTRESOLVED" : "RESOLVED=" + resolved);
            return 0;
        }
        catch
        {
            Console.Out.Write("NOTRESOLVED");
            return 0;
        }
    }

    /// <summary>
    /// Child-process entry point. Adds <paramref name="addDir"/> to the DLL search path, resolves
    /// <paramref name="dllName"/> via the loader, and prints "RESOLVED=&lt;path&gt;" or "NOTRESOLVED".
    /// </summary>
    /// <param name="traditional">
    /// When <c>true</c> the child uses the classic Windows search order
    /// (SetCurrentDirectory + LoadLibraryW with no flags) instead of the modern
    /// opt-in LOAD_LIBRARY_SEARCH_* flags.  Pass for Service-triggered candidates
    /// whose host binaries typically have not opted in to the secure search order.
    /// </param>
    public static int RunChild(string addDir, string dllName, bool traditional = false)
    {
        try
        {
            IntPtr h;
            if (traditional)
            {
                // Classic search order: place the writable directory as the current
                // directory so it becomes slot 1 of the traditional 6-slot sequence.
                if (Directory.Exists(addDir)) SetCurrentDirectory(addDir);
                h = LoadLibraryW(dllName);
            }
            else
            {
                if (Directory.Exists(addDir))
                    NativeMethods.AddDllDirectory(addDir);

                uint flags = NativeMethods.LOAD_LIBRARY_SEARCH_USER_DIRS
                           | NativeMethods.LOAD_LIBRARY_SEARCH_SYSTEM32
                           | NativeMethods.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
                           | NativeMethods.LOAD_LIBRARY_SEARCH_APPLICATION_DIR;
                h = NativeMethods.LoadLibraryExW(dllName, IntPtr.Zero, flags);
            }
            if (h == IntPtr.Zero)
            {
                // Report WHY the load failed (e.g. 225 = blocked by AV/Defender,
                // 577/1260 = code-integrity / application-control policy, 126 = not found).
                Console.Out.Write("NOTRESOLVED:" + System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                return 0;
            }

            var sb = new StringBuilder(1024);
            NativeMethods.GetModuleFileNameW(h, sb, 1024);
            NativeMethods.FreeLibrary(h);

            string resolved = sb.ToString();
            Console.Out.Write(string.IsNullOrEmpty(resolved) ? "NOTRESOLVED" : "RESOLVED=" + resolved);
            return 0;
        }
        catch
        {
            Console.Out.Write("NOTRESOLVED");
            return 0;
        }
    }

    /// <summary>Parent-side: probe every candidate (opt-in). Mutates candidate.LoadProbe + Notes.</summary>
    public static void VerifyAll(List<HijackCandidate> candidates, ScanProfile profile,
        CancellationToken cancellationToken = default)
    {
        if (!CanaryDllBuilder.TryGetProbeDll(out string probeDll))
        {
            AnsiConsole.MarkupLine("[yellow]Load-order verification skipped: probe DLL unavailable.[/]");
            return;
        }

        string? selfExe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(selfExe))
        {
            AnsiConsole.MarkupLine("[yellow]Load-order verification skipped: cannot locate self for child probe.[/]");
            return;
        }

        AnsiConsole.MarkupLine("[dim]Each candidate's writable position is briefly written with a " +
            "benign probe DLL, resolved by the real loader, then restored.[/]");

        int wins = 0, loses = 0, inconclusive = 0, skipped = 0;

        AnsiConsole.Progress().Start(ctx =>
        {
            var task = ctx.AddTask("[green]Verifying load order[/]", maxValue: candidates.Count);
            foreach (var c in candidates)
            {
                if (cancellationToken.IsCancellationRequested) break;
                task.Increment(1);

                Probe(c, probeDll, selfExe!, profile.LoadProbeTimeoutSeconds);
                switch (c.LoadProbe)
                {
                    case LoadProbeResult.Wins: wins++; break;
                    case LoadProbeResult.LosesToProtected: loses++; break;
                    case LoadProbeResult.Skipped: skipped++; break;
                    default: inconclusive++; break;
                }
            }
        });

        AnsiConsole.MarkupLine($"  [green]Verified-win: {wins}[/] | " +
            $"[red]Loses to protected (likely FP): {loses}[/] | " +
            $"[yellow]Inconclusive: {inconclusive}[/] | [grey]Skipped: {skipped}[/]");
        ScanLogger.Debug($"Load probe: {wins} win, {loses} lose, {inconclusive} inconclusive, {skipped} skipped");
    }

    private static void Probe(HijackCandidate c, string probeDll, string selfExe, int timeoutSec)
    {
        // Only types whose precedence over System32 is faithfully modeled by adding the writable
        // directory as a user search dir.
        if (c.Type is not (HijackType.Phantom or HijackType.SearchOrder or HijackType.SideLoad))
        {
            c.LoadProbe = LoadProbeResult.Skipped;
            c.Notes.Add($"Load probe skipped: {c.Type} precedence is not faithfully modeled by the probe.");
            return;
        }

        string target = c.HijackWritablePath;
        string? dir = Path.GetDirectoryName(target);
        string dll = Path.GetFileName(target);
        if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(dll) || !Directory.Exists(dir))
        {
            c.LoadProbe = LoadProbeResult.Skipped;
            c.Notes.Add("Load probe skipped: writable directory does not exist.");
            return;
        }

        string? backup = null;
        bool placed = false;
        try
        {
            if (File.Exists(target))
            {
                backup = target + ".probebak";
                File.Copy(target, backup, true);
            }

            File.Copy(probeDll, target, true);
            placed = true;

            // Choose the model that matches where the writable position sits:
            //  • the target's own directory → "appdir" (app dir precedes System32). The old
            //    CWD model placed it AFTER System32 and wrongly reported LosesToProtected
            //    for any DLL that also exists in System32.
            //  • otherwise, service binaries typically use the classic search order (CWD slot),
            //    everything else the modern SEARCH_USER_DIRS order.
            string? binaryDir = null;
            try { binaryDir = Path.GetDirectoryName(c.BinaryPath); } catch { }
            string mode = PathsEqual(dir!, binaryDir ?? "")
                ? "appdir"
                : c.Trigger == TriggerType.Service ? "traditional" : "modern";
            string output = RunResolveChild(selfExe, dir!, dll, timeoutSec, mode);

            if (output.StartsWith("RESOLVED=", StringComparison.Ordinal))
            {
                string resolved = output["RESOLVED=".Length..].Trim();
                c.LoadProbeResolvedPath = resolved;
                if (PathsEqual(resolved, target))
                {
                    c.LoadProbe = LoadProbeResult.Wins;
                    c.Notes.Add("✓ Load-order verified: a DLL at the writable position wins the loader's search.");
                }
                else
                {
                    c.LoadProbe = LoadProbeResult.LosesToProtected;
                    c.Notes.Add($"Load-order probe: the loader resolves '{dll}' to a protected path " +
                        $"instead ({resolved}) — likely NOT hijackable via this position " +
                        "(KnownDLL / System32 / SxS precedence).");
                }
            }
            else
            {
                c.LoadProbe = LoadProbeResult.NotResolved;
                string detail = DescribeLoadFailure(output);
                c.Notes.Add("Load-order probe: the name did not resolve even with a probe placed" +
                    (detail.Length > 0 ? $" ({detail})." : "."));
                ScanLogger.Debug($"Load probe NotResolved for {target} [{mode}]: {output}");
            }
        }
        catch (Exception ex)
        {
            c.LoadProbe = LoadProbeResult.Error;
            c.Notes.Add($"Load-order probe error: {ex.Message}");
        }
        finally
        {
            // Remove the probe and restore any original file.
            try { if (placed && File.Exists(target)) File.Delete(target); }
            catch { c.Notes.Add("Warning: load probe DLL could not be removed (file may be locked)."); }

            if (backup != null && File.Exists(backup))
            {
                try { File.Move(backup, target, true); }
                catch { c.Notes.Add("Warning: original DLL could not be restored after load probe — manual cleanup may be required."); }
            }

            // The probe is the canary build; loading it in the child writes a confirm file. Clean it.
            try { File.Delete(CanaryDllBuilder.GetConfirmPath(target)); } catch { }
        }
    }

    private static string RunResolveChild(string selfExe, string dir, string dll,
        int timeoutSec, string mode)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = selfExe,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("--resolve-probe");
            psi.ArgumentList.Add(dir);
            psi.ArgumentList.Add(dll);
            if (mode != "modern") psi.ArgumentList.Add(mode);

            using var p = Process.Start(psi);
            if (p == null) return "NOTRESOLVED:child-not-started";

            string output = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(Math.Max(1, timeoutSec) * 1000))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                return "NOTRESOLVED:timeout";
            }
            return output.Trim();
        }
        catch (Exception ex)
        {
            return "NOTRESOLVED:child-error " + ex.Message;
        }
    }

    private static string DescribeLoadFailure(string output)
    {
        int colon = output.IndexOf(':');
        if (colon < 0) return "";
        string tail = output[(colon + 1)..].Trim();
        if (!int.TryParse(tail, out int err))
            return tail;                                   // timeout / child-error text
        if (err == 0) return "";

        string meaning = err switch
        {
            2 or 126 => "module not found",
            5 => "access denied",
            193 => "not a valid image for this architecture",
            225 => "blocked by antivirus — the probe DLL was flagged",
            577 or 1260 or 4551 => "blocked by code-integrity / application-control policy",
            1114 => "DllMain initialisation failed",
            _ => new System.ComponentModel.Win32Exception(err).Message
        };
        return $"loader error {err}: {meaning}";
    }

    private static bool PathsEqual(string a, string b)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(a).TrimEnd('\\'),
                Path.GetFullPath(b).TrimEnd('\\'),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }
    }
}
