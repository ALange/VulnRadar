using System.Text.Json;
using System.Text.Json.Serialization;

namespace VulnRadar.State;

/// <summary>Represents a change that warrants alerting.</summary>
public class Change
{
    public string CveId { get; set; } = "";
    public string ChangeType { get; set; } = "";
    public double? OldValue { get; set; }
    public double? NewValue { get; set; }

    public override string ToString() => ChangeType switch
    {
        "NEW_CVE" => $"🆕 NEW: {CveId}",
        "NEW_KEV" => $"⚠️ NOW IN KEV: {CveId}",
        "NEW_PATCHTHIS" => $"🔥 EXPLOIT INTEL: {CveId} (PoC Available)",
        "BECAME_CRITICAL" => $"🚨 NOW CRITICAL: {CveId}",
        "EPSS_SPIKE" => $"📈 EPSS SPIKE: {CveId} ({FormatPct(OldValue)} → {FormatPct(NewValue)})",
        _ => $"{ChangeType}: {CveId}",
    };

    private static string FormatPct(double? val) =>
        val.HasValue ? $"{val.Value * 100.0:F1}%" : "N/A";
}

internal class StateData
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; set; } = 1;

    [JsonPropertyName("last_run")]
    public string? LastRun { get; set; }

    [JsonPropertyName("seen_cves")]
    public Dictionary<string, SeenCveEntry> SeenCves { get; set; } = new();

    [JsonPropertyName("statistics")]
    public StatisticsData Statistics { get; set; } = new();
}

internal class SeenCveEntry
{
    [JsonPropertyName("first_seen")]
    public string? FirstSeen { get; set; }

    [JsonPropertyName("last_seen")]
    public string? LastSeen { get; set; }

    [JsonPropertyName("alerted_at")]
    public string? AlertedAt { get; set; }

    [JsonPropertyName("alerted_channels")]
    public List<string> AlertedChannels { get; set; } = new();

    [JsonPropertyName("snapshot")]
    public CveSnapshot Snapshot { get; set; } = new();
}

public class CveSnapshot
{
    [JsonPropertyName("is_critical")]
    public bool IsCritical { get; set; }

    [JsonPropertyName("active_threat")]
    public bool ActiveThreat { get; set; }

    [JsonPropertyName("in_patchthis")]
    public bool InPatchthis { get; set; }

    [JsonPropertyName("probability_score")]
    public double? ProbabilityScore { get; set; }

    [JsonPropertyName("cvss_score")]
    public double? CvssScore { get; set; }
}

internal class StatisticsData
{
    [JsonPropertyName("total_alerts_sent")]
    public int TotalAlertsSent { get; set; }

    [JsonPropertyName("alerts_by_channel")]
    public Dictionary<string, int> AlertsByChannel { get; set; } = new();
}

/// <summary>Manages persistent state to track seen CVEs and prevent duplicate alerts.</summary>
public class StateManager
{
    private const int SchemaVersion = 1;

    public string Path { get; }
    private StateData _data;

    public string? LastRun => _data.LastRun;

    public StateManager(string path)
    {
        Path = path;
        _data = Load();
    }

    private StateData Load()
    {
        if (!File.Exists(Path)) return EmptyState();

        try
        {
            var text = File.ReadAllText(Path);
            var data = JsonSerializer.Deserialize<StateData>(text,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (data == null) return EmptyState();
            if (data.SchemaVersion != SchemaVersion)
            {
                Console.WriteLine("State schema version mismatch, resetting state");
                return EmptyState();
            }
            return data;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Could not load state file ({ex.Message}), starting fresh");
            return EmptyState();
        }
    }

    private static StateData EmptyState() => new StateData();

    /// <summary>Save state to file atomically (write-then-rename).</summary>
    public void Save()
    {
        _data.LastRun = DateTime.UtcNow.ToString("o");
        var dir = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(_data, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        });

        var tmp = Path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, Path, overwrite: true);
    }

    /// <summary>Check if this CVE has never been seen before.</summary>
    public bool IsNewCve(string cveId) => !_data.SeenCves.ContainsKey(cveId);

    /// <summary>Get the previous snapshot for a CVE.</summary>
    public CveSnapshot? GetSnapshot(string cveId)
    {
        if (!_data.SeenCves.TryGetValue(cveId, out var entry)) return null;
        return entry.Snapshot;
    }

    /// <summary>Detect changes that warrant alerting.</summary>
    public List<Change> DetectChanges(string cveId, VulnRadar.Parsers.RadarItem item)
    {
        var changes = new List<Change>();
        var previous = GetSnapshot(cveId);

        if (previous == null)
        {
            changes.Add(new Change { CveId = cveId, ChangeType = "NEW_CVE" });
            return changes;
        }

        if (item.ActiveThreat && !previous.ActiveThreat)
            changes.Add(new Change { CveId = cveId, ChangeType = "NEW_KEV", OldValue = 0, NewValue = 1 });

        if (item.InPatchthis && !previous.InPatchthis)
            changes.Add(new Change { CveId = cveId, ChangeType = "NEW_PATCHTHIS", OldValue = 0, NewValue = 1 });

        if (item.IsCritical && !previous.IsCritical)
            changes.Add(new Change { CveId = cveId, ChangeType = "BECAME_CRITICAL", OldValue = 0, NewValue = 1 });

        if (previous.ProbabilityScore.HasValue && item.ProbabilityScore.HasValue)
        {
            var delta = item.ProbabilityScore.Value - previous.ProbabilityScore.Value;
            if (delta >= 0.3)
                changes.Add(new Change
                {
                    CveId = cveId,
                    ChangeType = "EPSS_SPIKE",
                    OldValue = previous.ProbabilityScore,
                    NewValue = item.ProbabilityScore,
                });
        }

        return changes;
    }

    /// <summary>Update the stored snapshot for a CVE.</summary>
    public void UpdateSnapshot(string cveId, VulnRadar.Parsers.RadarItem item)
    {
        var now = DateTime.UtcNow.ToString("o");

        if (!_data.SeenCves.ContainsKey(cveId))
        {
            _data.SeenCves[cveId] = new SeenCveEntry
            {
                FirstSeen = now,
                LastSeen = now,
                AlertedAt = null,
                AlertedChannels = new List<string>(),
                Snapshot = new CveSnapshot(),
            };
        }

        var entry = _data.SeenCves[cveId];
        entry.LastSeen = now;
        entry.Snapshot = new CveSnapshot
        {
            IsCritical = item.IsCritical,
            ActiveThreat = item.ActiveThreat,
            InPatchthis = item.InPatchthis,
            ProbabilityScore = item.ProbabilityScore,
            CvssScore = item.CvssScore,
        };
    }

    /// <summary>Mark a CVE as alerted on specific channels.</summary>
    public void MarkAlerted(string cveId, IEnumerable<string> channels)
    {
        if (!_data.SeenCves.TryGetValue(cveId, out var entry)) return;

        var now = DateTime.UtcNow.ToString("o");
        entry.AlertedAt = now;

        var existing = new HashSet<string>(entry.AlertedChannels);
        foreach (var ch in channels) existing.Add(ch);
        entry.AlertedChannels = existing.OrderBy(c => c).ToList();

        foreach (var ch in channels)
        {
            _data.Statistics.TotalAlertsSent++;
            if (!_data.Statistics.AlertsByChannel.ContainsKey(ch))
                _data.Statistics.AlertsByChannel[ch] = 0;
            _data.Statistics.AlertsByChannel[ch]++;
        }
    }

    /// <summary>Remove CVEs not seen in the specified number of days.</summary>
    public int PruneOldEntries(int days = 180)
    {
        var cutoff = DateTime.UtcNow.AddDays(-days).ToString("o");
        var toRemove = _data.SeenCves
            .Where(kv => string.Compare(kv.Value.LastSeen ?? "", cutoff) < 0)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in toRemove)
            _data.SeenCves.Remove(key);

        return toRemove.Count;
    }

    /// <summary>Get summary statistics.</summary>
    public Dictionary<string, object> GetStats() => new()
    {
        ["total_tracked"] = _data.SeenCves.Count,
        ["total_alerts_sent"] = _data.Statistics.TotalAlertsSent,
        ["alerts_by_channel"] = _data.Statistics.AlertsByChannel,
        ["last_run"] = _data.LastRun ?? "(never)",
    };

    /// <summary>Get the first_seen date for a CVE.</summary>
    public string? GetFirstSeen(string cveId) =>
        _data.SeenCves.TryGetValue(cveId, out var e) ? e.FirstSeen : null;

    /// <summary>Enumerate all tracked CVEs with their data.</summary>
    public IEnumerable<(string CveId, string? FirstSeen)> GetAllTracked() =>
        _data.SeenCves.Select(kv => (kv.Key, kv.Value.FirstSeen));
}
