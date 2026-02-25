using System.Net.Http.Json;
using System.Text.Json;
using VulnRadar.Parsers;
using VulnRadar.State;

namespace VulnRadar.Notifications;

/// <summary>Send VulnRadar alerts via Discord webhooks using embed format.</summary>
public class DiscordProvider : NotificationProvider
{
    public override string Name => "discord";
    public override double RateLimitDelay { get; set; } = 0.5;

    private readonly string _webhookUrl;
    private readonly HttpClient _httpClient;

    public DiscordProvider(string webhookUrl, int maxAlerts = 10, HttpClient? httpClient = null)
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

        int color;
        string priority;
        if (isCritical) { color = 0xFF0000; priority = "🚨 CRITICAL"; }
        else if (kev) { color = 0xFFA500; priority = "⚠️ KEV"; }
        else { color = 0x3498DB; priority = "ℹ️ ALERT"; }

        if (changes != null && changes.Count > 0)
        {
            var changeStr = string.Join(" | ", changes.Select(c => c.ToString()));
            desc = $"**Change:** {changeStr}\n\n{desc}";
        }

        var kevDue = item.Kev?.DueDate ?? "";

        var fields = new List<object>
        {
            new { name = "EPSS", value = FormatEpss(epss), inline = true },
            new { name = "CVSS", value = FormatCvss(cvss), inline = true },
            new { name = "KEV", value = kev ? "✅ Yes" : "❌ No", inline = true },
            new { name = "Exploit Intel", value = patch ? "✅ Yes" : "❌ No", inline = true },
        };
        if (!string.IsNullOrEmpty(kevDue))
            fields.Add(new { name = "KEV Due Date", value = kevDue, inline = true });

        var payload = new
        {
            embeds = new[]
            {
                new
                {
                    title = $"{priority}: {cveId}",
                    description = string.IsNullOrEmpty(desc) ? "No description available." : desc,
                    color,
                    fields,
                    url = $"https://www.cve.org/CVERecord?id={cveId}",
                    footer = new { text = "VulnRadar Alert" },
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
                $"• [{i.CveId}](https://www.cve.org/CVERecord?id={i.CveId}) (EPSS: {FormatEpss(i.ProbabilityScore)})\n"))
            : "No critical findings.";

        var color = criticalCount > 0 ? 0xFF0000 : 0x00FF00;
        var changesSummary = BuildChangesSummary(changesByCve);

        var fields = new List<object>
        {
            new { name = "Total CVEs", value = total.ToString(), inline = true },
            new { name = "🚨 Critical", value = criticalCount.ToString(), inline = true },
            new { name = "⚠️ CISA KEV", value = kevCount.ToString(), inline = true },
            new { name = "🔥 Exploit Intel", value = patchCount.ToString(), inline = true },
        };
        if (!string.IsNullOrEmpty(changesSummary))
            fields.Add(new { name = "📊 Changes Since Last Run", value = changesSummary, inline = false });
        fields.Add(new { name = "Top Critical Findings", value = topList, inline = false });

        var payload = new
        {
            embeds = new[]
            {
                new
                {
                    title = "📊 VulnRadar Summary",
                    color,
                    fields,
                    footer = new { text = $"Repo: {repo}" },
                }
            }
        };

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
                $"{(i.ActiveThreat ? "🔴" : "⚪")} [{i.CveId}](https://www.cve.org/CVERecord?id={i.CveId}) (EPSS: {FormatEpss(i.ProbabilityScore)})\n"))
            : "No critical findings.";

        var monitoringParts = new List<string>();
        if (vendors?.Count > 0) monitoringParts.Add($"**Vendors:** {string.Join(", ", vendors)}");
        if (products?.Count > 0) monitoringParts.Add($"**Products:** {string.Join(", ", products)}");
        var monitoringText = monitoringParts.Count > 0 ? string.Join("\n", monitoringParts) : "_No watchlist configured_";

        var payload = new
        {
            embeds = new[]
            {
                new
                {
                    title = "🚀 VulnRadar Baseline Established",
                    description = "**First run complete!** Your vulnerability baseline has been established.\n\n" +
                        "Going forward, you'll only receive alerts for:\n" +
                        "• 🆕 New CVEs matching your watchlist\n" +
                        "• ⚠️ CVEs added to CISA KEV\n" +
                        "• 🔥 CVEs added to PatchThis\n" +
                        "• 📈 Significant EPSS increases",
                    color = 0x00FF00,
                    fields = new List<object>
                    {
                        new { name = "📋 Monitoring", value = monitoringText, inline = false },
                        new { name = "Total CVEs", value = total.ToString(), inline = true },
                        new { name = "🚨 Critical", value = criticalCount.ToString(), inline = true },
                        new { name = "⚠️ CISA KEV", value = kevCount.ToString(), inline = true },
                        new { name = "🔥 Exploit Intel", value = patchCount.ToString(), inline = true },
                        new { name = "Top 10 Critical (by EPSS)", value = topList, inline = false },
                    },
                    footer = new { text = repo },
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
