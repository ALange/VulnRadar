using VulnRadar.Parsers;
using VulnRadar.State;

namespace VulnRadar.Notifications;

/// <summary>Base class for all VulnRadar notification providers.</summary>
public abstract class NotificationProvider
{
    public abstract string Name { get; }
    public virtual int MaxAlerts { get; set; } = 10;
    public virtual double RateLimitDelay { get; set; } = 0.5;

    /// <summary>Send an individual CVE alert.</summary>
    public abstract void SendAlert(RadarItem item, List<Change>? changes = null);

    /// <summary>Send a summary with stats and top findings.</summary>
    public abstract void SendSummary(
        List<RadarItem> items,
        string repo,
        Dictionary<string, (RadarItem Item, List<Change> Changes)>? changesByCve = null);

    /// <summary>Send a first-run baseline establishment message.</summary>
    public abstract void SendBaseline(
        List<RadarItem> items,
        List<RadarItem> criticalItems,
        string repo,
        List<string>? vendors = null,
        List<string>? products = null);

    protected string BuildChangesSummary(
        Dictionary<string, (RadarItem Item, List<Change> Changes)>? changesByCve)
    {
        if (changesByCve == null || changesByCve.Count == 0) return "";

        var newCount = changesByCve.Values.Count(x => x.Changes.Any(c => c.ChangeType == "NEW_CVE"));
        var kevAdded = changesByCve.Values.Count(x => x.Changes.Any(c => c.ChangeType == "NEW_KEV"));
        var patchAdded = changesByCve.Values.Count(x => x.Changes.Any(c => c.ChangeType == "NEW_PATCHTHIS"));
        var epssSpike = changesByCve.Values.Count(x => x.Changes.Any(c => c.ChangeType == "EPSS_SPIKE"));

        var parts = new List<string>();
        if (newCount > 0) parts.Add($"🆕 {newCount} new");
        if (kevAdded > 0) parts.Add($"⚠️ {kevAdded} added to KEV");
        if (patchAdded > 0) parts.Add($"🔥 {patchAdded} new exploit intel");
        if (epssSpike > 0) parts.Add($"📈 {epssSpike} EPSS spike");
        return parts.Count > 0 ? string.Join(" | ", parts) : "No significant changes";
    }

    protected List<RadarItem> TopCritical(List<RadarItem> items, int n = 5)
    {
        return items
            .Where(i => i.IsCritical)
            .OrderByDescending(i => i.ProbabilityScore ?? 0)
            .Take(n)
            .ToList();
    }

    protected static string FormatEpss(double? epss) => CveParsers.FormatEpss(epss);
    protected static string FormatCvss(double? cvss) => CveParsers.FormatCvss(cvss);
}
