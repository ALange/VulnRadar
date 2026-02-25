using System.Net.Http.Json;
using VulnRadar.Parsers;
using VulnRadar.State;

namespace VulnRadar.Notifications;

/// <summary>Send VulnRadar alerts via Microsoft Teams webhooks using Adaptive Cards.</summary>
public class TeamsProvider : NotificationProvider
{
    public override string Name => "teams";
    public override double RateLimitDelay { get; set; } = 0.5;

    private readonly string _webhookUrl;
    private readonly HttpClient _httpClient;

    public TeamsProvider(string webhookUrl, int maxAlerts = 10, HttpClient? httpClient = null)
    {
        _webhookUrl = webhookUrl;
        MaxAlerts = maxAlerts;
        _httpClient = httpClient ?? new HttpClient();
    }

    public override void SendAlert(RadarItem item, List<Change>? changes = null)
    {
        var cveId = item.CveId;
        var desc = item.Description.Length > 500 ? item.Description[..500] : item.Description;
        var epss = item.ProbabilityScore;
        var cvss = item.CvssScore;
        var kev = item.ActiveThreat;
        var patch = item.InPatchthis;
        var isCritical = item.IsCritical;

        string priority, color;
        if (isCritical) { priority = "🚨 CRITICAL"; color = "attention"; }
        else if (kev) { priority = "⚠️ KEV"; color = "warning"; }
        else { priority = "ℹ️ ALERT"; color = "accent"; }

        if (changes != null && changes.Count > 0)
        {
            var changeStr = string.Join(" | ", changes.Select(c => c.ToString()));
            desc = $"**Change:** {changeStr}\n\n{desc}";
        }

        var cveUrl = $"https://www.cve.org/CVERecord?id={cveId}";

        var payload = BuildAdaptiveCardPayload(new List<object>
        {
            new { type = "TextBlock", text = $"{priority}: {cveId}", weight = "Bolder", size = "Large", color },
            new { type = "TextBlock", text = string.IsNullOrEmpty(desc) ? "No description available." : desc, wrap = true },
            new { type = "FactSet", facts = new List<object>
            {
                new { title = "EPSS", value = FormatEpss(epss) },
                new { title = "CVSS", value = FormatCvss(cvss) },
                new { title = "KEV", value = kev ? "✅ Yes" : "❌ No" },
                new { title = "PatchThis", value = patch ? "✅ Yes" : "❌ No" },
            }},
        }, new List<object>
        {
            new { type = "Action.OpenUrl", title = "View CVE Details", url = cveUrl },
        });

        PostJson(payload);
    }

    public override void SendSummary(
        List<RadarItem> items,
        string repo,
        Dictionary<string, (RadarItem Item, List<Change> Changes)>? changesByCve = null)
    {
        var total = items.Count;
        var criticalCount = items.Count(i => i.IsCritical);
        var kevCount = items.Count(i => i.ActiveThreat);
        var patchCount = items.Count(i => i.InPatchthis);

        var top5 = TopCritical(items, 5);
        var topList = top5.Count > 0
            ? string.Join("", top5.Select(i =>
                $"- [{i.CveId}](https://www.cve.org/CVERecord?id={i.CveId}) (EPSS: {FormatEpss(i.ProbabilityScore)})\n"))
            : "No critical findings.";

        var color = criticalCount > 0 ? "attention" : "good";
        var changesSummary = BuildChangesSummary(changesByCve);

        var body = new List<object>
        {
            new { type = "TextBlock", text = "📊 VulnRadar Summary", weight = "Bolder", size = "Large" },
            new { type = "ColumnSet", columns = new List<object>
            {
                MakeColumn("Total CVEs", total.ToString(), color),
                MakeColumn("🚨 Critical", criticalCount.ToString(), "attention"),
                MakeColumn("⚠️ KEV", kevCount.ToString(), "warning"),
                MakeColumn("🔥 Exploit Intel", patchCount.ToString(), "default"),
            }},
        };

        if (!string.IsNullOrEmpty(changesSummary))
            body.Add(new { type = "TextBlock", text = $"**📊 Changes Since Last Run:** {changesSummary}", wrap = true, spacing = "Medium" });

        body.Add(new { type = "TextBlock", text = "**Top Critical Findings:**", weight = "Bolder", spacing = "Medium" });
        body.Add(new { type = "TextBlock", text = topList, wrap = true });
        body.Add(new { type = "TextBlock", text = $"Repo: {repo}", size = "Small", isSubtle = true, spacing = "Medium" });

        PostJson(BuildAdaptiveCardPayload(body, null));
    }

    public override void SendBaseline(
        List<RadarItem> items,
        List<RadarItem> criticalItems,
        string repo,
        List<string>? vendors = null,
        List<string>? products = null)
    {
        var total = items.Count;
        var criticalCount = criticalItems.Count;
        var kevCount = items.Count(i => i.ActiveThreat);
        var patchCount = items.Count(i => i.InPatchthis);

        var sorted = criticalItems.OrderByDescending(i => i.ProbabilityScore ?? 0).Take(10).ToList();
        var topList = sorted.Count > 0
            ? string.Join("", sorted.Select(i =>
                $"- {(i.ActiveThreat ? "🔴" : "⚪")} [{i.CveId}](https://www.cve.org/CVERecord?id={i.CveId}) (EPSS: {FormatEpss(i.ProbabilityScore)})\n"))
            : "No critical findings.";

        var monitoringParts = new List<string>();
        if (vendors?.Count > 0) monitoringParts.Add($"**Vendors:** {string.Join(", ", vendors)}");
        if (products?.Count > 0) monitoringParts.Add($"**Products:** {string.Join(", ", products)}");
        var monitoringText = monitoringParts.Count > 0 ? string.Join("\n\n", monitoringParts) : "_No watchlist configured_";

        var body = new List<object>
        {
            new { type = "TextBlock", text = "🚀 VulnRadar Baseline Established", weight = "Bolder", size = "Large", color = "Good" },
            new { type = "TextBlock", text =
                "**First run complete!** Your vulnerability baseline has been established.\n\n" +
                "Going forward, you'll only receive alerts for:\n" +
                "- 🆕 New CVEs matching your watchlist\n" +
                "- ⚠️ CVEs added to CISA KEV\n" +
                "- 🔥 CVEs added to PatchThis\n" +
                "- 📈 Significant EPSS increases", wrap = true },
            new { type = "TextBlock", text = "**📋 Monitoring:**", weight = "Bolder", spacing = "Medium" },
            new { type = "TextBlock", text = monitoringText, wrap = true },
            new { type = "ColumnSet", columns = new List<object>
            {
                MakeColumn("Total CVEs", total.ToString(), "default"),
                MakeColumn("🚨 Critical", criticalCount.ToString(), "Attention"),
                MakeColumn("⚠️ KEV", kevCount.ToString(), "Warning"),
                MakeColumn("🔥 Exploit Intel", patchCount.ToString(), "default"),
            }},
            new { type = "TextBlock", text = "**Top 10 Critical (by EPSS):**", weight = "Bolder", spacing = "Medium" },
            new { type = "TextBlock", text = topList, wrap = true },
            new { type = "TextBlock", text = repo, size = "Small", isSubtle = true, spacing = "Medium" },
        };

        PostJson(BuildAdaptiveCardPayload(body, null));
    }

    private static object MakeColumn(string label, string value, string color) => new
    {
        type = "Column",
        width = "stretch",
        items = new List<object>
        {
            new { type = "TextBlock", text = label, weight = "Bolder" },
            new { type = "TextBlock", text = value, size = "ExtraLarge", color },
        }
    };

    private static object BuildAdaptiveCardPayload(List<object> body, List<object>? actions) => new
    {
        type = "message",
        attachments = new[]
        {
            new
            {
                contentType = "application/vnd.microsoft.card.adaptive",
                content = new
                {
                    schema = "http://adaptivecards.io/schemas/adaptive-card.json",
                    type = "AdaptiveCard",
                    version = "1.4",
                    body,
                    actions = actions ?? new List<object>(),
                }
            }
        }
    };

    private void PostJson(object payload)
    {
        var response = _httpClient.PostAsJsonAsync(_webhookUrl, payload).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
    }
}
