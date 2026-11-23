using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Safety;
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

        int confirmed = 0, failed = 0, skipped = 0, blocked = 0;

        // R3: one snapshot of every service this phase may touch, before anything changes.
        // Every later decision (pre-stop, restore) uses it, never a per-candidate query.
        foreach (var svc in candidates.Where(c => c.Trigger == TriggerType.Service)
                     .Select(c => c.TriggerIdentifier).Where(n => !string.IsNullOrWhiteSpace(n))
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var s = await ServiceControl.EnsureSnapshotAsync(svc);
            ScanLogger.Info($"Service snapshot: {svc} state={s.State} start={s.StartType} pid={s.Pid}");
        }

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
                        else if (candidate.CanaryResult == CanaryResult.Blocked)
                            blocked++;
                        else
                            failed++;
                    }
                    catch (IOException ex) when ((ex.HResult & 0xFFFF) == 225) // ERROR_VIRUS_INFECTED
                    {
                        candidate.CanaryResult = CanaryResult.Blocked;
                        candidate.Notes.Add($"Canary blocked by antivirus while deploying: {ex.Message}");
                        blocked++;
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
            $"[red]Failed: {failed}[/] | [yellow]Skipped: {skipped}[/]" +
            (blocked > 0 ? $" | [yellow]AV-blocked: {blocked}[/]" : ""));
        if (blocked > 0)
            AnsiConsole.MarkupLine("  [yellow]⚠ Antivirus removed the canary for some candidates — those results are " +
                "inconclusive. Exclude the target directories and %ProgramData%\\DLLHijackHunter on a test machine.[/]");
        ScanLogger.Debug($"Canary results: {confirmed} confirmed, {failed} failed, {skipped} skipped");

        // Cleanup all canary artifacts
        CanaryDllBuilder.CleanupAll();

        // R3: end of the canary phase: every touched service back in its snapshot state.
        foreach (var r in await ServiceControl.RestoreAllAsync("canary-phase"))
            ScanSession.AddResidue(r);

        return candidates;
    }

    private async Task TestCandidate(HijackCandidate candidate)
    {
        string canaryId = Guid.NewGuid().ToString("N")[..12];

        try
        {
            // Never stop, restart or plant for a protected or security-product service: it gets
            // no canary at all. Discovery and the finding itself are unchanged.
            if (candidate.Trigger == TriggerType.Service)
            {
                var (guarded, why) = ServiceControl.Guard(candidate.TriggerIdentifier);
                if (guarded)
                {
                    candidate.CanaryResult = CanaryResult.NotTested;
                    candidate.Notes.Add($"Canary not run: service guard refused '{candidate.TriggerIdentifier}' — {why}. " +
                        "The tool never stops or restarts protected or security-product services.");
                    Audit.Record(canaryId, candidate, "service-stop", candidate.TriggerIdentifier,
                        "refused-by-guard: " + why);
                    return;
                }
            }

            var fs = ScanSession.Files;
            var manifest = ScanSession.Manifest;
            string deploy = candidate.HijackWritablePath;
            void Act(string action, string target, string result) =>
                Audit.Record(canaryId, candidate, action, target, result);

            // Every file the canary places is recorded in the artifact manifest first. Without
            // a manifest nothing could be swept after a crash, so the canary does not run.
            if (manifest == null || !manifest.Trusted)
            {
                candidate.CanaryResult = CanaryResult.NotTested;
                candidate.Notes.Add("Canary not run: the artifact manifest is unavailable, so placed files " +
                    "could not be tracked." + (manifest?.LoadProblem is string p ? $" ({p})" : ""));
                return;
            }

            // Never treat a DLLHijackHunter artifact at the deploy path as the original: don't
            // back it up, proxy it or restore it. Report it as residue instead.
            var (deployKind, artifactWhy) = ClassifyExistingDeployFile(deploy, manifest, fs);
            if (deployKind == DeployPathKind.ToolArtifact)
            {
                candidate.CanaryResult = CanaryResult.NotTested;
                candidate.Notes.Add("Canary not run: deploy path holds a previous DLLHijackHunter artifact " +
                    $"({artifactWhy}). It was not proxied or backed up; it is reported as residue.");
                Act("file-inspect", deploy, "previous-artifact: " + artifactWhy);
                ScanSession.AddResidue(new ResidueEntry
                {
                    Path = deploy,
                    Role = ArtifactRole.Canary,
                    Sha256 = fs.Sha256(deploy),
                    Holder = fs.FindLockHolders(deploy),
                    CandidateId = candidate.Id,
                    Reason = $"deploy path holds a previous DLLHijackHunter artifact ({artifactWhy})"
                });
                return;
            }
            bool hadExistingDll = deployKind == DeployPathKind.Original;

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
            // A tool artifact is never an original.
            string? originalForProxy = null;
            try
            {
                if (hadExistingDll && PEAnalyzer.GetExportEntries(deploy).Count > 0)
                    originalForProxy = deploy;
                else if (!string.IsNullOrEmpty(candidate.DllLegitPath) &&
                         File.Exists(candidate.DllLegitPath!) &&
                         !ArtifactPaths.IsToolArtifact(candidate.DllLegitPath!, manifest) &&
                         !CanaryMarker.FileHasMarker(candidate.DllLegitPath!) &&
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
                deploy
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
            string canaryHash = ArtifactHash.OfFile(canaryInfo.DllPath) ?? "";

            // Clear any stale confirmation file at the derived path so a previous run cannot be
            // mistaken for this one.
            try
            {
                if (File.Exists(canaryInfo.ConfirmPath))
                {
                    File.Delete(canaryInfo.ConfirmPath);
                    Act("file-deleted", canaryInfo.ConfirmPath, "stale confirmation");
                }
            }
            catch
            {
            }

            string? backupPath = null;
            string? sidecarPath = null;   // proxy forward target, staged before deploy
            string? sidecarHash = null;
            string? originalHash = hadExistingDll ? fs.Sha256(deploy) : null;
            bool deployAttempted = false;

            // R3: the service's state comes from the scan's snapshot, never a per-candidate query
            // (a query during the previous candidate's START_PENDING read "not running" and the
            // service was then never restarted).
            bool serviceWasRunning = candidate.Trigger == TriggerType.Service &&
                ServiceControl.WasRunningAtSnapshot(candidate.TriggerIdentifier);

            // Pre-deploy service stop: a running service keeps the DLL mapped and its file
            // handle open, which would cause File.Copy to fail with a sharing violation.
            // Stop it here so we can overwrite the DLL. TriggerExecutor restarts it as
            // part of the confirmation trigger, and the finally block restores the original
            // running state once testing is complete.
            if (candidate.Trigger == TriggerType.Service && serviceWasRunning)
            {
                await ServiceControl.StopAsync(candidate.TriggerIdentifier, 5000, canaryId, candidate);
                await Task.Delay(1500); // allow the service process to exit and unload the DLL
            }

            // Stop the trigger again before retrying a locked delete (guard-checked for services).
            Func<Task> stopAgain = () => TriggerExecutor.StopTriggerAsync(candidate, canaryId);

            try
            {
                // Backup existing DLL if present
                if (hadExistingDll)
                {
                    backupPath = deploy + ".hijackhunter.bak";
                    if (!ScanSession.TryRecord(new ArtifactEntry
                        {
                            Path = backupPath, Role = ArtifactRole.Backup, Sha256 = originalHash,
                            CandidateId = candidate.Id, RestoreTo = deploy
                        }, out string? recErr))
                    {
                        backupPath = null;
                        FailHarness(candidate, CanaryFailureCauses.CouldNotBackUp,
                            $"Could not backup existing DLL: artifact manifest not writable ({recErr})");
                        return;
                    }
                    try
                    {
                        fs.Copy(deploy, backupPath, true);
                        Act("file-backed-up", deploy, "-> " + backupPath);
                    }
                    catch (Exception ex)
                    {
                        if (!fs.Exists(backupPath)) ScanSession.Forget(backupPath);
                        backupPath = null;
                        FailHarness(candidate, CanaryFailureCauses.CouldNotBackUp, $"Could not backup existing DLL: {ex.Message}");
                        return;
                    }
                }

                // Ensure target directory exists
                string? targetDir = Path.GetDirectoryName(deploy);
                if (targetDir != null && !Directory.Exists(targetDir))
                {
                    // For .local hijacks, create the .local directory
                    if (candidate.Type == HijackType.DotLocal)
                    {
                        try
                        {
                            Directory.CreateDirectory(targetDir);
                            Act("directory-created", targetDir, "ok");
                        }
                        catch
                        {
                            FailHarness(candidate, CanaryFailureCauses.TargetDirectoryMissing, "Could not create .local directory");
                            return;
                        }
                    }
                    else
                    {
                        FailHarness(candidate, CanaryFailureCauses.TargetDirectoryMissing, "Target directory does not exist");
                        return;
                    }
                }

                // Stage the proxy sidecar (the forward target): a copy of the original under a
                // distinct name beside the deploy location, so the proxy's forwarders resolve to
                // real code instead of to the canary itself. Must happen BEFORE the deploy copy,
                // which overwrites the original at HijackWritablePath.
                if (canaryInfo.IsProxy && originalForProxy != null)
                {
                    string sc = CanaryDllBuilder.GetSidecarPath(deploy);
                    if (fs.Exists(sc))
                    {
                        // Only a sidecar this tool recorded may be replaced; anything else stays.
                        var se = manifest.Find(sc);
                        string? cur = fs.Sha256(sc);
                        if (se == null || !string.Equals(se.Sha256, cur, StringComparison.OrdinalIgnoreCase))
                        {
                            FailHarness(candidate, CanaryFailureCauses.CouldNotStageSidecar,
                                $"Could not stage proxy sidecar: {sc} is occupied by a file DLLHijackHunter did not record; not overwritten");
                            return;
                        }
                        var left = await ArtifactCleaner.RemoveAsync(sc, ArtifactRole.Sidecar, cur, candidate.Id, fs, null, null, Act);
                        if (left != null)
                        {
                            ScanSession.AddResidue(left);
                            FailHarness(candidate, CanaryFailureCauses.CouldNotStageSidecar,
                                $"Could not stage proxy sidecar: a previous sidecar at {sc} could not be removed");
                            return;
                        }
                        ScanSession.Forget(sc);
                    }

                    sidecarHash = fs.Sha256(originalForProxy);
                    if (!ScanSession.TryRecord(new ArtifactEntry
                        { Path = sc, Role = ArtifactRole.Sidecar, Sha256 = sidecarHash, CandidateId = candidate.Id }, out string? scErr))
                    {
                        FailHarness(candidate, CanaryFailureCauses.CouldNotStageSidecar,
                            $"Could not stage proxy sidecar: artifact manifest not writable ({scErr})");
                        return;
                    }
                    sidecarPath = sc;
                    try
                    {
                        fs.Copy(originalForProxy, sc, true);
                        Act("file-planted", sc, "sidecar copy of " + originalForProxy);
                    }
                    catch (Exception ex)
                    {
                        FailHarness(candidate, CanaryFailureCauses.CouldNotStageSidecar, $"Could not stage proxy sidecar: {ex.Message}");
                        return;
                    }
                }

                // Deploy canary DLL (recorded first, with the confirm file it will write).
                if (!ScanSession.TryRecord(new ArtifactEntry
                        { Path = canaryInfo.ConfirmPath, Role = ArtifactRole.Confirm, CandidateId = candidate.Id }, out _) ||
                    !ScanSession.TryRecord(new ArtifactEntry
                        { Path = deploy, Role = ArtifactRole.Canary, Sha256 = canaryHash, CandidateId = candidate.Id }, out string? depErr))
                {
                    candidate.CanaryResult = CanaryResult.NotTested;
                    candidate.Notes.Add("Canary not run: artifact manifest not writable, the canary would be untracked.");
                    return;
                }
                deployAttempted = true;
                fs.Copy(canaryInfo.DllPath, deploy, true);
                DateTime plantedUtc = DateTime.UtcNow;
                Act("file-planted", deploy, canaryInfo.IsProxy ? "proxy canary" : "precompiled canary");

                // Trigger execution. For a Service trigger this returns once the service is stably
                // RUNNING (ServiceControl waits for it), plus a short grace.
                bool triggered = await TriggerExecutor.TriggerAsync(
                    candidate, _profile.CanaryTimeoutSeconds, canaryId);
                DateTime triggeredUtc = DateTime.UtcNow;
                // Reference for the fire time: when the service reached RUNNING (the audit line of
                // this candidate's own start, recorded once the state was stable), else the trigger.
                DateTime referenceUtc;
                string reference;
                lock (candidate.CanaryActions)
                {
                    var start = candidate.CanaryActions.LastOrDefault(a => a.Action == "service-start");
                    (referenceUtc, reference) = candidate.Trigger == TriggerType.Service && start != null && start.Utc >= plantedUtc
                        ? (start.Utc, "service RUNNING")
                        : (triggeredUtc, "trigger");
                }

                // If execution could not be triggered at all, fail immediately.
                if (!triggered)
                {
                    FailHarness(candidate, CanaryFailureCauses.CouldNotTrigger, "Could not trigger execution context " +
                        "(service may be running, access denied, or dependency chain issue)");
                }
                else
                {
                    // R2: poll for the confirmation file. A Service trigger waits up to the
                    // service wait (default 90 s) after the service is stably RUNNING: the service
                    // may start the process that loads the DLL long after it starts itself.
                    int waitMs = CanaryWait.ForTrigger(candidate.Trigger, _profile.CanarySettleSeconds,
                        _profile.CanaryServiceWaitSeconds);
                    Act("canary-wait", canaryInfo.ConfirmPath, $"waiting up to {waitMs / 1000} s from {reference}");
                    var waitClock = System.Diagnostics.Stopwatch.StartNew();
                    const int pollInterval = 1000;

                    while (true)
                    {
                        if (File.Exists(canaryInfo.ConfirmPath))
                        {
                            candidate.CanaryResult = CanaryResult.Fired;
                            candidate.Confidence = 100.0;
                            // Read the write time first: ParseConfirmation removes the confirm file.
                            DateTime confirmUtc = DateTime.UtcNow;
                            try
                            {
                                var t = File.GetLastWriteTimeUtc(canaryInfo.ConfirmPath);
                                if (t.Year > 2000) confirmUtc = t;   // 1601-01-01 = file already gone
                            }
                            catch { }
                            ParseConfirmation(candidate, canaryInfo.ConfirmPath);
                            string fired = CanaryWait.FiredText(referenceUtc, confirmUtc, reference) +
                                FormattableString.Invariant($" ({(confirmUtc - plantedUtc).TotalSeconds:0.0} s after plant)");
                            Act("canary-fired", canaryInfo.ConfirmPath, fired);
                            candidate.Notes.Add("Canary fired: " + fired);
                            break;
                        }
                        if (waitClock.ElapsedMilliseconds >= waitMs) break;
                        await Task.Delay(pollInterval);
                    }

                    if (candidate.CanaryResult != CanaryResult.Fired && !File.Exists(deploy))
                    {
                        // The canary vanished from the deploy location: real-time antivirus
                        // quarantined it. That says nothing about the hijack itself.
                        candidate.CanaryResult = CanaryResult.Blocked;
                        candidate.Notes.Add("Canary DLL was removed from the deploy location before it fired — " +
                            "most likely quarantined by antivirus. Inconclusive; exclude the directory on a " +
                            "test machine to confirm.");
                    }
                    else if (candidate.CanaryResult != CanaryResult.Fired)
                    {
                        Act("canary-wait", canaryInfo.ConfirmPath,
                            FormattableString.Invariant($"no confirm file {waitClock.Elapsed.TotalSeconds:0.0} s after {reference}"));
                        // R2: did the host crash or fail to load after the plant, naming the planted module?
                        var (result, cause, note) = CanaryOutcome.ClassifyNoFire(new HostEvidence(
                            plantedUtc, deploy, CanaryOutcome.ReadEventsSince(plantedUtc)));
                        if (result == CanaryResult.Failed && cause != null)
                        {
                            candidate.CanaryResult = CanaryResult.Failed;
                            candidate.CanaryFailureCause = cause;
                            candidate.Notes.Add(note!);
                            Act("host-failed-after-plant", deploy, note!);
                        }
                        else
                        {
                            candidate.CanaryResult = CanaryResult.Timeout;
                            string option = candidate.Trigger == TriggerType.Service ? "--canary-service-wait" : "--canary-settle";
                            candidate.Notes.Add(
                                $"Execution triggered but canary did not fire within {waitMs / 1000} s of the {reference}. " +
                                "The target may call SetDefaultDllDirectories(), use a hardened search order, " +
                                "or need specific conditions to load the DLL. " +
                                $"Try {option} <seconds> for a longer wait.");
                        }
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
                    await ServiceControl.StopAsync(candidate.TriggerIdentifier, 5000, canaryId, candidate);

                // Cleanup: remove the canary, but only if what sits there is still our canary.
                bool canaryGone = true;
                if (deployAttempted)
                {
                    string? cur = fs.Sha256(deploy);
                    if (cur != null && string.Equals(cur, canaryHash, StringComparison.OrdinalIgnoreCase))
                    {
                        var r = await ArtifactCleaner.RemoveAsync(deploy, ArtifactRole.Canary, canaryHash,
                            candidate.Id, fs, stopAgain, null, Act);
                        if (r == null) ScanSession.Forget(deploy);
                        else
                        {
                            canaryGone = false;
                            ScanSession.AddResidue(r);
                            candidate.Notes.Add("Warning: Could not remove canary DLL — file may be locked. " + DescribeResidue(r));
                        }
                    }
                    else
                    {
                        // Gone already (antivirus), or the deploy copy never replaced the original.
                        ScanSession.Forget(deploy);
                    }
                }

                // Restore backup
                if (backupPath != null && fs.Exists(backupPath))
                {
                    ResidueEntry? r;
                    if (canaryGone)
                        r = await ArtifactCleaner.RestoreAsync(backupPath, deploy, originalHash, candidate.Id, fs,
                            stopAgain, null, Act);
                    else
                    {
                        // The canary is still there (delete scheduled for reboot): schedule the
                        // original to be moved back after it, at the same reboot.
                        bool s = false;
                        try { s = fs.ScheduleMoveOnReboot(backupPath, deploy); } catch { }
                        Act("file-restore-delayed", deploy, s ? "scheduled for next reboot" : "could not schedule");
                        r = new ResidueEntry
                        {
                            Path = backupPath, Role = ArtifactRole.Backup, Sha256 = originalHash, CandidateId = candidate.Id,
                            DelayedDeleteScheduled = s, Holder = fs.FindLockHolders(deploy),
                            Reason = $"original could not be restored to {deploy}: the canary there is still locked"
                        };
                    }

                    if (r == null && string.Equals(fs.Sha256(deploy), originalHash, StringComparison.OrdinalIgnoreCase))
                        ScanSession.Forget(backupPath);
                    else if (r != null)
                    {
                        ScanSession.AddResidue(r);
                        candidate.Notes.Add("Warning: Could not restore original DLL from backup - file may be locked by a lingering process. " +
                            DescribeResidue(r));
                    }
                }
                else if (backupPath != null)
                {
                    ScanSession.Forget(backupPath);
                }

                // Remove the proxy sidecar (forward target) if we staged one.
                if (sidecarPath != null)
                {
                    if (fs.Exists(sidecarPath))
                    {
                        var r = await ArtifactCleaner.RemoveAsync(sidecarPath, ArtifactRole.Sidecar, sidecarHash,
                            candidate.Id, fs, stopAgain, null, Act);
                        if (r == null) ScanSession.Forget(sidecarPath);
                        else
                        {
                            ScanSession.AddResidue(r);
                            candidate.Notes.Add("Warning: Could not remove proxy sidecar — file may be locked. " + DescribeResidue(r));
                        }
                    }
                    else ScanSession.Forget(sidecarPath);
                }

                // The confirmation file (in the tool's own folder).
                try
                {
                    if (File.Exists(canaryInfo.ConfirmPath))
                    {
                        File.Delete(canaryInfo.ConfirmPath);
                        Act("file-deleted", canaryInfo.ConfirmPath, "confirmation");
                    }
                    if (!File.Exists(canaryInfo.ConfirmPath)) ScanSession.Forget(canaryInfo.ConfirmPath);
                }
                catch { }

                // Clean up .local directory if we created it
                if (candidate.Type == HijackType.DotLocal)
                {
                    string? dotLocalDir = Path.GetDirectoryName(deploy);
                    if (dotLocalDir != null)
                    {
                        try
                        {
                            if (Directory.Exists(dotLocalDir) &&
                                !Directory.EnumerateFileSystemEntries(dotLocalDir).Any())
                            {
                                Directory.Delete(dotLocalDir);
                                Act("directory-deleted", dotLocalDir, "ok");
                            }
                        }
                        catch
                        {
                        }
                    }
                }

                // R3: restore the service to its snapshot state, wait for a stable state and
                // verify (retried with backoff). A service that cannot be restored is residue.
                if (candidate.Trigger == TriggerType.Service &&
                    await ServiceControl.RestoreAsync(candidate.TriggerIdentifier, canaryId, candidate) is ResidueEntry left)
                {
                    ScanSession.AddResidue(left);
                    candidate.Notes.Add($"Warning: service {left.Service} could not be restored to {left.ExpectedState} " +
                        $"(left {left.ActualState}: {left.LastError}). Recorded as residue.");
                }
            }
        }
        finally
        {
            CanaryDllBuilder.Cleanup(canaryId);
        }
    }

    /// <summary>
    /// Failed because of the harness, not the hijack: no scoring penalty (see TieredScorer).
    /// </summary>
    private static void FailHarness(HijackCandidate candidate, string cause, string note)
    {
        candidate.CanaryResult = CanaryResult.Failed;
        candidate.CanaryFailureCause = cause;
        candidate.Notes.Add(note);
    }

    private static string DescribeResidue(ResidueEntry r) =>
        "Recorded as residue" +
        (r.Holder != null ? $"; held by {r.Holder}" : "") +
        (r.DelayedDeleteScheduled ? "; scheduled for removal at next reboot." : "; NOT scheduled — manual cleanup required.");

    /// <summary>
    /// What sits at a canary deploy path before the canary is placed. A file the tool wrote
    /// (listed in the manifest with the same hash, or carrying the canary marker) is never an
    /// "original": it must not be backed up, proxied or restored.
    /// </summary>
    internal static (DeployPathKind kind, string reason) ClassifyExistingDeployFile(string path,
        ArtifactManifest? manifest, IFileOps fs)
    {
        if (!fs.Exists(path)) return (DeployPathKind.Absent, "");

        string? hash = fs.Sha256(path);
        var entry = manifest?.Find(path);
        if (entry != null && hash != null &&
            string.Equals(entry.Sha256, hash, StringComparison.OrdinalIgnoreCase))
            return (DeployPathKind.ToolArtifact,
                $"listed in the artifact manifest as a {entry.Role} from scan {entry.ScanId}");
        if (hash != null && manifest != null &&
            manifest.Entries.FirstOrDefault(e => string.Equals(e.Sha256, hash, StringComparison.OrdinalIgnoreCase))
                is ArtifactEntry copy && copy.Role != ArtifactRole.Backup && copy.Role != ArtifactRole.Sidecar)
            return (DeployPathKind.ToolArtifact, $"same content as artifact {copy.Path} from scan {copy.ScanId}");
        if (CanaryMarker.FileHasMarker(path))
            return (DeployPathKind.ToolArtifact, "carries the DLLHijackHunter canary marker");
        return (DeployPathKind.Original, "");
    }

    /// <summary>
    /// COM objects whose code runs in (or as) the activating client: InprocServer32 ("VARIES")
    /// and LocalServer32 without a fixed RunAs identity. A fixed RunAs / LocalService server
    /// is launched by the COM SCM under its configured account, so its canary identity is real.
    /// </summary>
    private static bool IsCallerContextCom(HijackCandidate candidate) =>
        candidate.Trigger == TriggerType.COM &&
        candidate.RunAsAccount is "VARIES" or "Launching User" or "Interactive User" or "";

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

            string observedUser = data.GetValueOrDefault("USER", "Unknown");
            string observedIntegrity = data.GetValueOrDefault("INTEGRITY", "Unknown");
            bool observedSeDebug = data.GetValueOrDefault("SE_DEBUG", "NO")
                .Equals("YES", StringComparison.OrdinalIgnoreCase);

            if (IsCallerContextCom(candidate))
            {
                // The COM trigger activates the object from a PowerShell process spawned by this
                // (elevated) scanner. For in-proc / launching-user servers the canary therefore
                // runs with the SCANNER's token — proof that the DLL loads, but not of the
                // privilege an attacker would gain. Do not let it inflate impact scoring.
                candidate.ConfirmedPrivilege = "Caller context (scanner-activated)";
                candidate.ConfirmedIntegrityLevel = "n/a";
                candidate.ConfirmedSeDebug = null;
                candidate.Notes.Add("✓ CANARY CONFIRMED: DLL load verified. Identity observed " +
                    $"({observedUser}, {observedIntegrity} integrity) is the scanner-launched COM " +
                    "client, not the victim — real privilege depends on which process activates this object.");
            }
            else
            {
                candidate.ConfirmedPrivilege = observedUser;
                candidate.ConfirmedIntegrityLevel = observedIntegrity;
                candidate.ConfirmedSeDebug = observedSeDebug;

                candidate.Notes.Add($"✓ CANARY CONFIRMED: Running as {candidate.ConfirmedPrivilege} " +
                    $"at {candidate.ConfirmedIntegrityLevel} integrity" +
                    (candidate.ConfirmedSeDebug == true ? " with SeDebugPrivilege" : ""));
            }

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