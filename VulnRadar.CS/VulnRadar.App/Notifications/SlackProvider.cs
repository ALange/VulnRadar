using System.Net.Http.Json;
using VulnRadar.Parsers;
using VulnRadar.State;

namespace VulnRadar.Notifications;

/// <summary>Send VulnRadar alerts via Slack webhooks using Block Kit.</summary>
public class SlackProvider : NotificationProvider
{
    public override string Name => "slack";
    public override double RateLimitDelay { get; set; } = 1.0;

    private readonly string _webhookUrl;
    private readonly HttpClient _httpClient;

    public SlackProvider(string webhookUrl, int maxAlerts = 10, HttpClient? httpClient = null)
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
        if (isCritical) { priority = "🚨 *CRITICAL*"; color = "danger"; }
        else if (kev) { priority = "⚠️ *KEV*"; color = "warning"; }
        else { priority = "ℹ️ *ALERT*"; color = "#3498DB"; }

        if (changes != null && changes.Count > 0)
        {
            var changeStr = string.Join(" | ", changes.Select(c => c.ToString()));
            desc = $"*Change:* {changeStr}\n\n{desc}";
        }

        var cveUrl = $"https://www.cve.org/CVERecord?id={cveId}";

        var payload = new
        {
            attachments = new[]
            {
                new
                {
                    color,
                    blocks = new List<object>
                    {
                        new { type = "section", text = new { type = "mrkdwn", text = $"{priority}: <{cveUrl}|{cveId}>\n{desc}" } },
                        new { type = "section", fields = new List<object>
                        {
                            new { type = "mrkdwn", text = $"*EPSS:* {FormatEpss(epss)}" },
                            new { type = "mrkdwn", text = $"*CVSS:* {FormatCvss(cvss)}" },
                            new { type = "mrkdwn", text = $"*KEV:* {(kev ? "✅ Yes" : "❌ No")}" },
                            new { type = "mrkdwn", text = $"*PatchThis:* {(patch ? "✅ Yes" : "❌ No")}" },
                        }},
                        new { type = "context", elements = new[] { new { type = "mrkdwn", text = "VulnRadar Alert" } } },
                    }
                }
            }
        };

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
                $"• <https://www.cve.org/CVERecord?id={i.CveId}|{i.CveId}> (EPSS: {FormatEpss(i.ProbabilityScore)})\n"))
            : "No critical findings.";

        var color = criticalCount > 0 ? "danger" : "good";
        var changesSummary = BuildChangesSummary(changesByCve);

        var blocks = new List<object>
        {
            new { type = "header", text = new { type = "plain_text", text = "📊 VulnRadar Summary", emoji = true } },
            new { type = "section", fields = new List<object>
            {
                new { type = "mrkdwn", text = $"*Total CVEs:* {total}" },
                new { type = "mrkdwn", text = $"*🚨 Critical:* {criticalCount}" },
                new { type = "mrkdwn", text = $"*⚠️ CISA KEV:* {kevCount}" },
                new { type = "mrkdwn", text = $"*🔥 Exploit Intel:* {patchCount}" },
            }},
        };

        if (!string.IsNullOrEmpty(changesSummary))
            blocks.Add(new { type = "section", text = new { type = "mrkdwn", text = $"*📊 Changes Since Last Run:*\n{changesSummary}" } });

        blocks.Add(new { type = "section", text = new { type = "mrkdwn", text = $"*Top Critical Findings:*\n{topList}" } });
        blocks.Add(new { type = "context", elements = new[] { new { type = "mrkdwn", text = $"Repo: {repo}" } } });

        var payload = new { attachments = new[] { new { color, blocks } } };
        PostJson(payload);
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
                $"{(i.ActiveThreat ? "🔴" : "⚪")} <https://www.cve.org/CVERecord?id={i.CveId}|{i.CveId}> (EPSS: {FormatEpss(i.ProbabilityScore)})\n"))
            : "No critical findings.";

        var monitoringParts = new List<string>();
        if (vendors?.Count > 0) monitoringParts.Add($"*Vendors:* {string.Join(", ", vendors)}");
        if (products?.Count > 0) monitoringParts.Add($"*Products:* {string.Join(", ", products)}");
        var monitoringText = monitoringParts.Count > 0 ? string.Join("\n", monitoringParts) : "_No watchlist configured_";

        var payload = new
        {
            attachments = new[]
            {
                new
                {
                    color = "good",
                    blocks = new List<object>
                    {
                        new { type = "header", text = new { type = "plain_text", text = "🚀 VulnRadar Baseline Established", emoji = true } },
                        new { type = "section", text = new { type = "mrkdwn", text =
                            "*First run complete!* Your vulnerability baseline has been established.\n\n" +
                            "Going forward, you'll only receive alerts for:\n" +
                            "• 🆕 New CVEs matching your watchlist\n" +
                            "• ⚠️ CVEs added to CISA KEV\n" +
                            "• 🔥 CVEs added to PatchThis\n" +
                            "• 📈 Significant EPSS increases" }},
                        new { type = "section", text = new { type = "mrkdwn", text = $"*📋 Monitoring:*\n{monitoringText}" } },
                        new { type = "section", fields = new List<object>
                        {
                            new { type = "mrkdwn", text = $"*Total CVEs:* {total}" },
                            new { type = "mrkdwn", text = $"*🚨 Critical:* {criticalCount}" },
                            new { type = "mrkdwn", text = $"*⚠️ CISA KEV:* {kevCount}" },
                            new { type = "mrkdwn", text = $"*🔥 Exploit Intel:* {patchCount}" },
                        }},
                        new { type = "section", text = new { type = "mrkdwn", text = $"*Top 10 Critical (by EPSS):*\n{topList}" } },
                        new { type = "context", elements = new[] { new { type = "mrkdwn", text = repo } } },
                    }
                }
            }
        };

        PostJson(payload);
    }

    private void PostJson(object payload)
    {
        var response = _httpClient.PostAsJsonAsync(_webhookUrl, payload).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
    }
}
