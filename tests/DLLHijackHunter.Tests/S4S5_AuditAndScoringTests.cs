using DLLHijackHunter.Models;
using DLLHijackHunter.Safety;
using DLLHijackHunter.Scoring;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>S5: a refused or failed harness is not evidence against the hijack.</summary>
public class S5_ScoringTests
{
    private static HijackCandidate Candidate(CanaryResult result, string? cause = null) => new()
    {
        BinaryPath = @"C:\App\app.exe",
        DllName = "x.dll",
        Type = HijackType.Phantom,
        Trigger = TriggerType.Service,
        ServiceStartType = "AUTO_START",
        RunAsAccount = "NT AUTHORITY\\SYSTEM",
        Confidence = 60,
        CanaryResult = result,
        CanaryFailureCause = cause,
    };

    [Theory]
    [InlineData(CanaryFailureCauses.CouldNotTrigger)]
    [InlineData(CanaryFailureCauses.CouldNotBackUp)]
    [InlineData(CanaryFailureCauses.CouldNotStageSidecar)]
    [InlineData(CanaryFailureCauses.TargetDirectoryMissing)]
    public void HarnessCauseFailed_ScoresLikeNotTested(string cause)
    {
        var failed = Candidate(CanaryResult.Failed, cause);
        var notTested = Candidate(CanaryResult.NotTested);
        new TieredScorer().Score(failed);
        new TieredScorer().Score(notTested);

        Assert.Equal(notTested.Confidence, failed.Confidence);
        Assert.Equal(notTested.FinalScore, failed.FinalScore);
        Assert.Equal(notTested.Tier, failed.Tier);
        Assert.Contains(failed.Notes, n => n.Contains("inconclusive", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Timeout_StillCostsTen()
    {
        var c = Candidate(CanaryResult.Timeout);
        new TieredScorer().Score(c);
        Assert.Equal(50, c.Confidence);
    }

    [Fact]
    public void NotTested_HasNoPenalty()
    {
        var c = Candidate(CanaryResult.NotTested);
        new TieredScorer().Score(c);
        Assert.Equal(60, c.Confidence);
    }

    [Fact]
    public void FailedWithoutHarnessCause_KeepsMinusTwenty()
    {
        var c = Candidate(CanaryResult.Failed);
        new TieredScorer().Score(c);
        Assert.Equal(40, c.Confidence);
    }
}

/// <summary>S4: every side effect lands in the candidate's CanaryActions, in order.</summary>
public class S4_AuditTests
{
    [Fact]
    public void Record_AppendsOrderedActionsToCandidate()
    {
        var c = new HijackCandidate();
        Audit.Record("canary1", c, "file-planted", @"C:\w\x.dll", "ok");
        Audit.Record("canary1", c, "service-stop", "WinDefend", "refused-by-guard");
        Assert.Equal(2, c.CanaryActions.Count);
        Assert.Equal("file-planted", c.CanaryActions[0].Action);
        Assert.Equal("refused-by-guard", c.CanaryActions[1].Result);
        Assert.True(c.CanaryActions[0].Utc <= c.CanaryActions[1].Utc);
        Assert.Equal(DateTimeKind.Utc, c.CanaryActions[0].Utc.Kind);
    }
}
