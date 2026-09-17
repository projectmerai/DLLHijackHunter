using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;
using Spectre.Console;

namespace DLLHijackHunter.Canary;

public class CanaryEngine
{
    private readonly ScanProfile _profile;

    public CanaryEngine(ScanProfile profile)
    {
        _profile = profile;
    }

    public async Task<List<HijackCandidate>> ConfirmAsync(List<HijackCandidate> candidates,
        CancellationToken cancellationToken = default)
    {
        if (!_profile.RunCanary)
        {
            AnsiConsole.MarkupLine("[yellow]Canary confirmation disabled by profile.[/]");
            return candidates;
        }

        AnsiConsole.MarkupLine($"\n[bold cyan]═══ Canary Confirmation ({candidates.Count} candidates) ═══[/]");

        int confirmed = 0, failed = 0, skipped = 0;

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("[green]Testing candidates[/]", maxValue: candidates.Count);

                foreach (var candidate in candidates)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        AnsiConsole.MarkupLine("[yellow]Canary testing cancelled.[/]");
                        break;
                    }

                    task.Increment(1);

                    // Skip candidates that can't be triggered automatically
                    if (candidate.Trigger is TriggerType.Startup or TriggerType.RunKey or
                        TriggerType.Manual or TriggerType.Unknown or TriggerType.UACBypass)
                    {
                        candidate.CanaryResult = CanaryResult.NotTested;
                        candidate.Notes.Add("Canary not tested — requires manual trigger " +
                            "(reboot/logon/manual execution)");
                        skipped++;
                        continue;
                    }

                    try
                    {
                        await TestCandidate(candidate);
                        if (candidate.CanaryResult == CanaryResult.Fired)
                            confirmed++;
                        else
                            failed++;
                    }
                    catch (Exception ex)
                    {
                        candidate.CanaryResult = CanaryResult.Failed;
                        candidate.Notes.Add($"Canary error: {ex.Message}");
                        failed++;
                    }
                }
            });

        AnsiConsole.MarkupLine($"  [green]Confirmed: {confirmed}[/] | " +
            $"[red]Failed: {failed}[/] | [yellow]Skipped: {skipped}[/]");
        ScanLogger.Debug($"Canary results: {confirmed} confirmed, {failed} failed, {skipped} skipped");

        // Cleanup all canary artifacts
        CanaryDllBuilder.CleanupAll();

        return candidates;
    }

    private async Task TestCandidate(HijackCandidate candidate)
    {
        string canaryId = Guid.NewGuid().ToString("N")[..12];

        try
        {
            // Determine architecture
            bool is64Bit = true;
            try
            {
                var pe = PEAnalyzer.Analyze(candidate.BinaryPath);
                is64Bit = pe.Is64Bit;
            }
            catch
            {
            }

            // Resolve the "original" DLL whose exports must be preserved so a host that binds
            // them at load time (a static import) keeps resolving after we deploy the canary.
            // Prefer the DLL already sitting at the deploy path; else the known legit copy. If
            // neither exports anything it is a true phantom — the export-less canary is correct.
            string? originalForProxy = null;
            try
            {
                if (File.Exists(candidate.HijackWritablePath) &&
                    PEAnalyzer.GetExportEntries(candidate.HijackWritablePath).Count > 0)
                    originalForProxy = candidate.HijackWritablePath;
                else if (!string.IsNullOrEmpty(candidate.DllLegitPath) &&
                         File.Exists(candidate.DllLegitPath!) &&
                         PEAnalyzer.GetExportEntries(candidate.DllLegitPath!).Count > 0)
                    originalForProxy = candidate.DllLegitPath;
            }
            catch
            {
            }

            // Build canary DLL. The confirmation path is derived from the deploy location
            // (HijackWritablePath), which is exactly where the canary will be loaded from.
            var canaryInfo = CanaryDllBuilder.BuildCanary(
                canaryId,
                candidate.DllName,
                originalForProxy,
                is64Bit,
                candidate.HijackWritablePath
            );

            if (canaryInfo.IsProxy)
            {
                candidate.Notes.Add("Canary generated as a runtime-synthesized export-forwarding " +
                    "proxy (no toolchain required): every export of the original is forwarded to a " +
                    "sidecar copy, so the host keeps working and DllMain still fires.");
            }
            else if (originalForProxy != null)
            {
                candidate.Notes.Add("Canary is the export-less precompiled build: runtime proxy " +
                    "synthesis was unavailable, so a host that binds this DLL's exports at load " +
                    "time may fail to load and confirmation may not fire.");
            }

            // Check if DLL was obtained successfully
            if (string.IsNullOrEmpty(canaryInfo.DllPath) || !File.Exists(canaryInfo.DllPath))
            {
                candidate.CanaryResult = CanaryResult.NotTested;
                candidate.Notes.Add("Could not obtain a canary DLL (embedded precompiled canary missing and no MSVC toolchain available).");
                return;
            }

            // Clear any stale confirmation file at the derived path so a previous run cannot be
            // mistaken for this one.
            try
            {
                if (File.Exists(canaryInfo.ConfirmPath))
                    File.Delete(canaryInfo.ConfirmPath);
            }
            catch
            {
            }

            // Backup existing DLL if present
            string? backupPath = null;
            string? sidecarPath = null;   // proxy forward target, staged before deploy
            bool hadExistingDll = File.Exists(candidate.HijackWritablePath);

            // Record initial service state
            bool serviceWasRunning = false;
            if (candidate.Trigger == TriggerType.Service)
            {
                try
                {
                    var queryPsi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"query \"{candidate.TriggerIdentifier}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    };

                    using var queryProc = System.Diagnostics.Process.Start(queryPsi);
                    string queryOut = queryProc?.StandardOutput.ReadToEnd() ?? string.Empty;
                    queryProc?.WaitForExit(2000);
                    serviceWasRunning = queryOut.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
                }
                catch
                {
                }
            }

            // Pre-deploy service stop: a running service keeps the DLL mapped and its file
            // handle open, which would cause File.Copy to fail with a sharing violation.
            // Stop it here so we can overwrite the DLL. TriggerExecutor restarts it as
            // part of the confirmation trigger, and the finally block restores the original
            // running state once testing is complete.
            if (candidate.Trigger == TriggerType.Service && serviceWasRunning)
            {
                try
                {
                    var preStopPsi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"stop \"{candidate.TriggerIdentifier}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using var preStopProc = System.Diagnostics.Process.Start(preStopPsi);
                    preStopProc?.WaitForExit(5000);
                    await Task.Delay(1500); // allow the service process to exit and unload the DLL
                }
                catch
                {
                }
            }

            if (hadExistingDll)
            {
                backupPath = candidate.HijackWritablePath + ".hijackhunter.bak";
                try
                {
                    File.Copy(candidate.HijackWritablePath, backupPath, true);
                }
                catch (Exception ex)
                {
                    candidate.CanaryResult = CanaryResult.Failed;
                    candidate.Notes.Add($"Could not backup existing DLL: {ex.Message}");
                    return;
                }
            }

            try
            {
                // Ensure target directory exists
                string? targetDir = Path.GetDirectoryName(candidate.HijackWritablePath);
                if (targetDir != null && !Directory.Exists(targetDir))
                {
                    // For .local hijacks, create the .local directory
                    if (candidate.Type == HijackType.DotLocal)
                    {
                        try
                        {
                            Directory.CreateDirectory(targetDir);
                        }
                        catch
                        {
                            candidate.CanaryResult = CanaryResult.Failed;
                            candidate.Notes.Add("Could not create .local directory");
                            return;
                        }
                    }
                    else
                    {
                        candidate.CanaryResult = CanaryResult.Failed;
                        candidate.Notes.Add("Target directory does not exist");
                        return;
                    }
                }

                // Stage the proxy sidecar (the forward target): a copy of the original under a
                // distinct name beside the deploy location, so the proxy's forwarders resolve to
                // real code instead of to the canary itself. Must happen BEFORE the deploy copy,
                // which overwrites the original at HijackWritablePath.
                if (canaryInfo.IsProxy && originalForProxy != null)
                {
                    sidecarPath = CanaryDllBuilder.GetSidecarPath(candidate.HijackWritablePath);
                    try
                    {
                        File.Copy(originalForProxy, sidecarPath, true);
                    }
                    catch (Exception ex)
                    {
                        candidate.CanaryResult = CanaryResult.Failed;
                        candidate.Notes.Add($"Could not stage proxy sidecar: {ex.Message}");
                        return;
                    }
                }

                // Deploy canary DLL
                File.Copy(canaryInfo.DllPath, candidate.HijackWritablePath, true);

                // Trigger execution
                bool triggered = await TriggerExecutor.TriggerAsync(
                    candidate, _profile.CanaryTimeoutSeconds);

                // If execution could not be triggered at all, fail immediately.
                if (!triggered)
                {
                    candidate.CanaryResult = CanaryResult.Failed;
                    candidate.Notes.Add("Could not trigger execution context " +
                        "(service may be running, access denied, or dependency chain issue)");
                }
                else
                {
                    // Poll for the confirmation file across the settle window so we catch both
                    // fast loaders (check every 2 s) and slow services (full CanarySettleSeconds).
                    int settleMs = _profile.CanarySettleSeconds * 1000;
                    int elapsed = 0;
                    const int pollInterval = 2000;

                    while (elapsed < settleMs)
                    {
                        await Task.Delay(pollInterval);
                        elapsed += pollInterval;

                        if (File.Exists(canaryInfo.ConfirmPath))
                        {
                            candidate.CanaryResult = CanaryResult.Fired;
                            candidate.Confidence = 100.0;
                            ParseConfirmation(candidate, canaryInfo.ConfirmPath);
                            break;
                        }
                    }

                    if (candidate.CanaryResult != CanaryResult.Fired)
                    {
                        candidate.CanaryResult = CanaryResult.Timeout;
                        candidate.Notes.Add(
                            $"Execution triggered but canary did not fire within {_profile.CanarySettleSeconds} s settle window. " +
                            "The target may call SetDefaultDllDirectories(), use a hardened search order, " +
                            "or need specific conditions to load the DLL. " +
                            "Try --canary-settle <seconds> for a longer wait.");
                    }
                }

                // Check if app is still functional (for search order hijacks)
                if (candidate.CanaryResult == CanaryResult.Fired &&
                    candidate.Type == HijackType.SearchOrder)
                {
                    candidate.AppStillFunctional = true; // proxy DLL should keep it working
                }
            }
            finally
            {
                // For services, stop first to reduce DLL/file locking before cleanup/restore
                if (candidate.Trigger == TriggerType.Service)
                {
                    try
                    {
                        var stopPsi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "sc.exe",
                            Arguments = $"stop \"{candidate.TriggerIdentifier}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using var stopProc = System.Diagnostics.Process.Start(stopPsi);
                        stopProc?.WaitForExit(5000);
                    }
                    catch
                    {
                    }
                }

                // Cleanup: remove canary DLL
                try
                {
                    if (File.Exists(candidate.HijackWritablePath))
                        File.Delete(candidate.HijackWritablePath);
                }
                catch
                {
                    candidate.Notes.Add("Warning: Could not remove canary DLL — file may be locked");
                }

                // Restore backup
                if (backupPath != null && File.Exists(backupPath))
                {
                    try
                    {
                        File.Move(backupPath, candidate.HijackWritablePath, true);
                    }
                    catch
                    {
                        candidate.Notes.Add("Warning: Could not restore original DLL from backup - file may be locked by a lingering process. Manual cleanup may be required.");
                    }
                }

                // Remove the proxy sidecar (forward target) if we staged one.
                if (sidecarPath != null && File.Exists(sidecarPath))
                {
                    try
                    {
                        File.Delete(sidecarPath);
                    }
                    catch
                    {
                        candidate.Notes.Add("Warning: Could not remove proxy sidecar — file may be locked. Manual cleanup may be required.");
                    }
                }

                // Clean up .local directory if we created it
                if (candidate.Type == HijackType.DotLocal)
                {
                    string? dotLocalDir = Path.GetDirectoryName(candidate.HijackWritablePath);
                    if (dotLocalDir != null)
                    {
                        try
                        {
                            if (Directory.Exists(dotLocalDir) &&
                                !Directory.EnumerateFileSystemEntries(dotLocalDir).Any())
                            {
                                Directory.Delete(dotLocalDir);
                            }
                        }
                        catch
                        {
                        }
                    }
                }

                // Restore service to its original state
                if (candidate.Trigger == TriggerType.Service && serviceWasRunning)
                {
                    try
                    {
                        await Task.Delay(1000);

                        var startPsi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "sc.exe",
                            Arguments = $"start \"{candidate.TriggerIdentifier}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };

                        using var startProc = System.Diagnostics.Process.Start(startPsi);
                        startProc?.WaitForExit(5000);
                    }
                    catch
                    {
                    }
                }
            }
        }
        finally
        {
            CanaryDllBuilder.Cleanup(canaryId);
        }
    }

    private static void ParseConfirmation(HijackCandidate candidate, string confirmPath)
    {
        try
        {
            var lines = File.ReadAllLines(confirmPath);
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in lines)
            {
                // Safely skip the informational header line formatted by snprintf
                if (line.StartsWith("[DllHijackHunter]", StringComparison.OrdinalIgnoreCase))
                    continue;

                int eq = line.IndexOf('=');
                if (eq > 0)
                {
                    string key = line[..eq].Trim();
                    string value = line[(eq + 1)..].Trim();
                    data[key] = value;
                }
            }

            candidate.ConfirmedPrivilege = data.GetValueOrDefault("USER", "Unknown");
            candidate.ConfirmedIntegrityLevel = data.GetValueOrDefault("INTEGRITY", "Unknown");
            candidate.ConfirmedSeDebug = data.GetValueOrDefault("SE_DEBUG", "NO")
                .Equals("YES", StringComparison.OrdinalIgnoreCase);

            candidate.Notes.Add($"✓ CANARY CONFIRMED: Running as {candidate.ConfirmedPrivilege} " +
                $"at {candidate.ConfirmedIntegrityLevel} integrity" +
                (candidate.ConfirmedSeDebug == true ? " with SeDebugPrivilege" : ""));

            try
            {
                File.Delete(confirmPath);
            }
            catch
            {
            }
        }
        catch (Exception ex)
        {
            candidate.Notes.Add($"Canary fired but could not parse confirmation: {ex.Message}");
        }
    }
}