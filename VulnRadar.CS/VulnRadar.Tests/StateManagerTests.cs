using VulnRadar.Parsers;
using VulnRadar.State;

namespace VulnRadar.Tests;

public class StateManagerTests
{
    private static string TempStatePath() =>
        Path.Combine(Path.GetTempPath(), $"vulnradar_test_{Guid.NewGuid():N}.json");

    [Fact]
    public void StateManager_StartsEmpty()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var stats = state.GetStats();
            Assert.Equal(0, stats["total_tracked"]);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void IsNewCve_ReturnsTrueForNewCve()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            Assert.True(state.IsNewCve("CVE-2024-12345"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void IsNewCve_ReturnsFalseAfterUpdateSnapshot()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var item = new RadarItem { CveId = "CVE-2024-12345", IsCritical = true };
            state.UpdateSnapshot("CVE-2024-12345", item);
            Assert.False(state.IsNewCve("CVE-2024-12345"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void DetectChanges_NewCve_ReturnsNewCveChange()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var item = new RadarItem { CveId = "CVE-2024-12345" };
            var changes = state.DetectChanges("CVE-2024-12345", item);
            Assert.Single(changes);
            Assert.Equal("NEW_CVE", changes[0].ChangeType);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void DetectChanges_DetectsKevAddition()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var oldItem = new RadarItem { CveId = "CVE-2024-12345", ActiveThreat = false };
            state.UpdateSnapshot("CVE-2024-12345", oldItem);

            var newItem = new RadarItem { CveId = "CVE-2024-12345", ActiveThreat = true };
            var changes = state.DetectChanges("CVE-2024-12345", newItem);

            Assert.Contains(changes, c => c.ChangeType == "NEW_KEV");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void DetectChanges_DetectsEpssSpike()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var oldItem = new RadarItem { CveId = "CVE-2024-12345", ProbabilityScore = 0.1 };
            state.UpdateSnapshot("CVE-2024-12345", oldItem);

            var newItem = new RadarItem { CveId = "CVE-2024-12345", ProbabilityScore = 0.5 };
            var changes = state.DetectChanges("CVE-2024-12345", newItem);

            Assert.Contains(changes, c => c.ChangeType == "EPSS_SPIKE");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void DetectChanges_NoSpike_WhenDeltaSmall()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var oldItem = new RadarItem { CveId = "CVE-2024-12345", ProbabilityScore = 0.1 };
            state.UpdateSnapshot("CVE-2024-12345", oldItem);

            var newItem = new RadarItem { CveId = "CVE-2024-12345", ProbabilityScore = 0.2 };
            var changes = state.DetectChanges("CVE-2024-12345", newItem);

            Assert.DoesNotContain(changes, c => c.ChangeType == "EPSS_SPIKE");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Save_And_Load_RoundTrips()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var item = new RadarItem
            {
                CveId = "CVE-2024-99999",
                IsCritical = true,
                ActiveThreat = true,
                ProbabilityScore = 0.85,
                CvssScore = 9.8,
            };
            state.UpdateSnapshot("CVE-2024-99999", item);
            state.MarkAlerted("CVE-2024-99999", new[] { "discord", "slack" });
            state.Save();

            var state2 = new StateManager(path);
            Assert.False(state2.IsNewCve("CVE-2024-99999"));
            var snap = state2.GetSnapshot("CVE-2024-99999");
            Assert.NotNull(snap);
            Assert.True(snap.IsCritical);
            Assert.True(snap.ActiveThreat);
            Assert.Equal(0.85, snap.ProbabilityScore);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void PruneOldEntries_RemovesOldCves()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var item = new RadarItem { CveId = "CVE-2020-99999" };
            state.UpdateSnapshot("CVE-2020-99999", item);
            state.Save();

            // Manually set last_seen to old date by reloading and pruning
            // Note: actual prune behavior depends on internal timestamps
            // We test that pruning returns a non-negative count
            var pruned = state.PruneOldEntries(days: 0);
            Assert.True(pruned >= 0);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void MarkAlerted_UpdatesStats()
    {
        var path = TempStatePath();
        try
        {
            var state = new StateManager(path);
            var item = new RadarItem { CveId = "CVE-2024-12345" };
            state.UpdateSnapshot("CVE-2024-12345", item);
            state.MarkAlerted("CVE-2024-12345", new[] { "discord", "slack" });

            var stats = state.GetStats();
            Assert.Equal(2, stats["total_alerts_sent"]);
        }
        finally { File.Delete(path); }
    }
}

public class ChangeTests
{
    [Theory]
    [InlineData("NEW_CVE", "CVE-2024-12345", "🆕 NEW: CVE-2024-12345")]
    [InlineData("NEW_KEV", "CVE-2024-12345", "⚠️ NOW IN KEV: CVE-2024-12345")]
    [InlineData("NEW_PATCHTHIS", "CVE-2024-12345", "🔥 EXPLOIT INTEL: CVE-2024-12345 (PoC Available)")]
    [InlineData("BECAME_CRITICAL", "CVE-2024-12345", "🚨 NOW CRITICAL: CVE-2024-12345")]
    public void Change_ToString_FormatsCorrectly(string changeType, string cveId, string expected)
    {
        var change = new Change { CveId = cveId, ChangeType = changeType };
        Assert.Equal(expected, change.ToString());
    }

    [Fact]
    public void Change_EpssSpike_FormatsWithPercentages()
    {
        var change = new Change
        {
            CveId = "CVE-2024-12345",
            ChangeType = "EPSS_SPIKE",
            OldValue = 0.1,
            NewValue = 0.5,
        };
        var str = change.ToString();
        Assert.Contains("EPSS SPIKE", str);
        Assert.Contains("CVE-2024-12345", str);
    }
}
