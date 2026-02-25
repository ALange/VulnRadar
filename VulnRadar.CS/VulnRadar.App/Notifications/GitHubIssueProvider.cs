using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using VulnRadar.Parsers;
using VulnRadar.State;

namespace VulnRadar.Notifications;

/// <summary>Create GitHub Issues for VulnRadar findings.</summary>
public class GitHubIssueProvider : NotificationProvider
{
    public override string Name => "github_issues";

    private readonly string _repo;
    private readonly string? _projectUrl;
    private readonly HttpClient _session;
    private HashSet<string>? _existingCves;
    private Dictionary<string, int>? _issueMap;
    private string? _projectId;

    private static readonly Regex CveRe = new(@"\bCVE-\d{4}-\d+\b", RegexOptions.IgnoreCase);

    public GitHubIssueProvider(
        string token,
        string repo,
        int maxAlerts = 25,
        string? projectUrl = null,
        HttpClient? httpClient = null)
    {
        _repo = repo;
        MaxAlerts = maxAlerts;
        _projectUrl = projectUrl;
        _session = httpClient ?? MakeSession(token);
    }

    private static HttpClient MakeSession(string token)
    {
        var client = new HttpClient();
        client.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
        client.DefaultRequestHeaders.Add("User-Agent", "VulnRadar-Notify/0.2");
        if (!string.IsNullOrEmpty(token))
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        return client;
    }

    // ─── GitHub API helpers ───────────────────────────────────────────────────

    private IEnumerable<JsonElement> IterRecentIssues(int maxPages = 3)
    {
        var baseUrl = $"https://api.github.com/repos/{_repo}/issues";
        for (var page = 1; page <= maxPages; page++)
        {
            var url = $"{baseUrl}?state=all&per_page=100&page={page}";
            var response = _session.GetAsync(url).GetAwaiter().GetResult();
            response.EnsureSuccessStatusCode();
            var text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var data = JsonDocument.Parse(text).RootElement;
            if (data.ValueKind != JsonValueKind.Array || data.GetArrayLength() == 0) yield break;

            foreach (var issue in data.EnumerateArray())
            {
                if (issue.ValueKind != JsonValueKind.Object) continue;
                if (issue.TryGetProperty("pull_request", out _)) continue;
                yield return issue;
            }
        }
    }

    private HashSet<string> LoadExistingCves()
    {
        if (_existingCves != null) return _existingCves;
        var out_ = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var issue in IterRecentIssues(maxPages: 4))
        {
            var title = issue.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "";
            if (!title.Contains("[VulnRadar]")) continue;
            var m = CveRe.Match(title);
            if (m.Success) out_.Add(m.Value.ToUpperInvariant());
        }
        _existingCves = out_;
        return out_;
    }

    private Dictionary<string, int> LoadIssueMap()
    {
        if (_issueMap != null) return _issueMap;
        var out_ = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var issue in IterRecentIssues(maxPages: 4))
        {
            var title = issue.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "";
            if (!title.Contains("[VulnRadar]")) continue;
            var state = issue.TryGetProperty("state", out var s) ? s.GetString() : null;
            if (state != "open") continue;
            var m = CveRe.Match(title);
            if (!m.Success) continue;
            var cveId = m.Value.ToUpperInvariant();
            if (issue.TryGetProperty("number", out var num) && !out_.ContainsKey(cveId))
                out_[cveId] = num.GetInt32();
        }
        _issueMap = out_;
        return out_;
    }

    private JsonElement? CreateIssue(string title, string body, List<string>? labels = null)
    {
        var url = $"https://api.github.com/repos/{_repo}/issues";
        var payload = new Dictionary<string, object> { ["title"] = title, ["body"] = body };
        if (labels != null) payload["labels"] = labels;

        var response = _session.PostAsJsonAsync(url, payload).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private void AddComment(int issueNumber, string body)
    {
        var url = $"https://api.github.com/repos/{_repo}/issues/{issueNumber}/comments";
        var response = _session.PostAsJsonAsync(url, new { body }).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
    }

    // ─── Issue body formatting ────────────────────────────────────────────────

    public static string FormatIssueBody(RadarItem item, List<Change>? changes = null)
    {
        var cveId = item.CveId;
        var desc = item.Description;
        var epss = CveParsers.FormatEpss(item.ProbabilityScore);
        var cvss = CveParsers.FormatCvss(item.CvssScore);
        var kev = item.ActiveThreat;
        var patch = item.InPatchthis;
        var isCritical = item.IsCritical;

        var lines = new List<string>
        {
            $"## {(isCritical ? "🚨 CRITICAL" : "⚠️ ALERT")}: [{cveId}](https://www.cve.org/CVERecord?id={cveId})",
            "",
            "---",
            "",
            "### 📊 Risk Metrics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            $"| EPSS Score | {epss} |",
            $"| CVSS Score | {cvss} |",
            $"| CVSS Severity | {item.CvssSeverity ?? "N/A"} |",
            $"| CISA KEV | {(kev ? "🔴 YES" : "⚪ No")} |",
            $"| Exploit Intel (PatchThis) | {(patch ? "🟠 YES" : "⚪ No")} |",
            $"| Priority | {(string.IsNullOrEmpty(item.PriorityLabel) ? "Standard" : item.PriorityLabel)} |",
            "",
            "---",
            "",
            "### 📝 Description",
            "",
            desc ?? "No description available.",
            "",
        };

        if (item.Kev != null)
        {
            lines.AddRange(new[]
            {
                "---", "",
                "### ⚠️ CISA KEV Details", "",
                $"- **Vulnerability Name:** {item.Kev.VulnerabilityName ?? "N/A"}",
                $"- **Vendor/Project:** {item.Kev.VendorProject ?? "N/A"}",
                $"- **Product:** {item.Kev.Product ?? "N/A"}",
                $"- **Date Added:** {item.Kev.DateAdded ?? "N/A"}",
                $"- **Required Action:** {item.Kev.RequiredAction ?? "N/A"}",
                $"- **Due Date:** {item.Kev.DueDate ?? "N/A"}",
                $"- **Ransomware Campaign:** {item.Kev.KnownRansomwareCampaignUse ?? "N/A"}",
                "",
            });
        }

        if (item.MatchedTerms.Count > 0)
        {
            lines.AddRange(new[]
            {
                "---", "",
                "### 🎯 Watchlist Matches", "",
                string.Join(", ", item.MatchedTerms.Select(t => $"`{t}`")),
                "",
            });
        }

        if (changes != null && changes.Count > 0)
        {
            lines.AddRange(new[]
            {
                "---", "",
                "### 🔄 Changes Detected", "",
            });
            foreach (var c in changes)
                lines.Add($"- {c}");
            lines.Add("");
        }

        lines.AddRange(new[]
        {
            "---",
            "",
            "### 🔗 Resources",
            "",
            $"- [CVE Record](https://www.cve.org/CVERecord?id={cveId})",
            $"- [NVD Entry](https://nvd.nist.gov/vuln/detail/{cveId})",
            $"- [EPSS Info](https://www.first.org/epss/)",
            $"- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
            "",
            "---",
            "_Generated by [VulnRadar](https://github.com/ALange/VulnRadar) (C# Edition)_",
        });

        return string.Join("\n", lines);
    }

    public static string FormatEscalationComment(Change change, RadarItem item)
    {
        return change.ChangeType switch
        {
            "NEW_KEV" => $"## ⚠️ NOW IN CISA KEV\n\n**{item.CveId}** has been added to the CISA Known Exploited Vulnerabilities catalog.\n\n" +
                (item.Kev?.DueDate != null ? $"**Action Required By:** {item.Kev.DueDate}\n\n" : "") +
                (item.Kev?.RequiredAction != null ? $"**Required Action:** {item.Kev.RequiredAction}\n\n" : "") +
                "_This CVE now requires immediate attention per CISA guidelines._",
            "NEW_PATCHTHIS" => $"## 🔥 EXPLOIT INTEL AVAILABLE\n\n**{item.CveId}** now has a known PoC exploit in the PatchThis database.\n\n" +
                $"**Current EPSS:** {CveParsers.FormatEpss(item.ProbabilityScore)}\n\n_Risk of exploitation has increased significantly._",
            "EPSS_SPIKE" => $"## 📈 EPSS SCORE SPIKE\n\n**{item.CveId}** has seen a significant increase in EPSS probability.\n\n" +
                $"**{change}**\n\n_Higher EPSS indicates increased likelihood of exploitation._",
            "BECAME_CRITICAL" => $"## 🚨 NOW CRITICAL\n\n**{item.CveId}** has been elevated to critical status.\n\n" +
                $"**Reason:** {(string.IsNullOrEmpty(item.PriorityLabel) ? "Multiple risk factors" : item.PriorityLabel)}",
            _ => $"## ℹ️ Update\n\n{change}",
        };
    }

    public static List<string> ExtractDynamicLabels(RadarItem item, int maxLabels = 3)
    {
        var labels = new List<string>();
        var severity = item.CvssSeverity?.ToLowerInvariant();
        if (!string.IsNullOrEmpty(severity) && severity != "none")
            labels.Add($"cvss-{severity}");
        if (item.Nvd?.CweIds?.Count > 0)
            labels.Add(item.Nvd.CweIds[0].ToLowerInvariant().Replace(" ", "-"));
        return labels.Take(maxLabels).ToList();
    }

    public static string? ExtractSeverityLabel(RadarItem item)
    {
        var cvss = item.CvssScore;
        if (!cvss.HasValue) return null;
        return cvss.Value switch
        {
            >= 9.0 => "severity-critical",
            >= 7.0 => "severity-high",
            >= 4.0 => "severity-medium",
            _ => "severity-low",
        };
    }

    // ─── NotificationProvider methods ────────────────────────────────────────

    public override void SendAlert(RadarItem item, List<Change>? changes = null)
    {
        // Individual alerts are handled via SendAll
    }

    public override void SendSummary(
        List<RadarItem> items,
        string repo,
        Dictionary<string, (RadarItem Item, List<Change> Changes)>? changesByCve = null)
    {
        // Weekly summary is separate
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

        var sorted = criticalItems.OrderByDescending(i => i.ProbabilityScore ?? 0).ToList();

        var monitoringLines = new List<string>();
        if (vendors?.Count > 0) monitoringLines.Add($"- **Vendors:** {string.Join(", ", vendors)}");
        if (products?.Count > 0) monitoringLines.Add($"- **Products:** {string.Join(", ", products)}");
        var monitoringText = monitoringLines.Count > 0 ? string.Join("\n", monitoringLines) : "_No watchlist configured_";

        var lines = new List<string>
        {
            "# 🚀 VulnRadar Baseline Established", "",
            "This is the **first run** of VulnRadar on this repository. Instead of creating individual issues for all existing findings, this summary establishes your baseline.", "",
            "## 📋 Monitoring", "",
            monitoringText, "",
            "**Going forward, VulnRadar will only create issues for:**",
            "- 🆕 New CVEs that match your watchlist",
            "- ⚠️ Existing CVEs newly added to CISA KEV",
            "- 🔥 Existing CVEs with new exploit intel (PoC available)",
            "- 📈 CVEs with significant EPSS increases (≥30%)", "",
            "---", "",
            "## 📊 Current State Summary", "",
            "| Metric | Count |",
            "|--------|-------|",
            $"| Total CVEs Tracked | {total} |",
            $"| 🚨 Critical (require action) | {criticalCount} |",
            $"| ⚠️ In CISA KEV | {kevCount} |",
            $"| 🔥 Exploit Intel (PoC) | {patchCount} |", "",
            "---", "",
            "## 🔴 Top 20 Critical Findings", "",
            "These are your highest-priority items based on EPSS score:", "",
            "| CVE ID | EPSS | CVSS | KEV | Exploit | Description |",
            "|--------|------|------|-----|-----------|-------------|",
        };

        foreach (var item in sorted.Take(20))
        {
            var cveId = item.CveId;
            var desc = (item.Description.Length > 60 ? item.Description[..60] : item.Description)
                .Replace("|", "\\|").Replace("\n", " ");
            var kev = item.ActiveThreat ? "🔴" : "⚪";
            var patch = item.InPatchthis ? "🟠" : "⚪";
            lines.Add($"| [{cveId}](https://www.cve.org/CVERecord?id={cveId}) | " +
                $"{CveParsers.FormatEpss(item.ProbabilityScore)} | " +
                $"{CveParsers.FormatCvss(item.CvssScore)} | {kev} | {patch} | {desc}... |");
        }

        if (sorted.Count > 20)
            lines.Add($"| ... | | | | | _and {sorted.Count - 20} more critical findings_ |");

        lines.AddRange(new[]
        {
            "", "---", "",
            "## 📋 Next Steps", "",
            "1. **Review the critical findings above** - these need attention",
            "2. **Check your watchlist** (`watchlist.yaml`) to ensure it covers your vendors/products",
            "3. **Close this issue** once you've reviewed the baseline", "",
            "Future VulnRadar runs will only alert on **new or changed** CVEs.", "",
            "---",
            "_Generated by [VulnRadar](https://github.com/ALange/VulnRadar) (C# Edition) - First Run Baseline_",
        });

        var body = string.Join("\n", lines);
        var title = $"[VulnRadar] 🚀 Baseline Established - {criticalCount} Critical Findings";
        CreateIssue(title, body, new List<string> { "vulnradar", "baseline" });
        Console.WriteLine($"Created baseline summary issue with {criticalCount} critical findings");
    }

    /// <summary>Create a weekly summary issue.</summary>
    public void CreateWeeklySummary(List<RadarItem> items, StateManager? state = null)
    {
        var now = DateTime.UtcNow;
        var weekAgo = now.AddDays(-7);
        var weekStart = weekAgo.ToString("MMM dd");
        var weekEnd = now.ToString("MMM dd, yyyy");

        var total = items.Count;
        var criticalCount = items.Count(i => i.IsCritical);
        var kevCount = items.Count(i => i.ActiveThreat);
        var patchCount = items.Count(i => i.InPatchthis);

        var newCvesThisWeek = 0;
        if (state != null)
        {
            foreach (var (_, firstSeen) in state.GetAllTracked())
            {
                if (firstSeen == null) continue;
                if (DateTime.TryParse(firstSeen, out var dt) && dt >= weekAgo)
                    newCvesThisWeek++;
            }
        }

        var criticalItems = items.Where(i => i.IsCritical)
            .OrderByDescending(i => i.ProbabilityScore ?? 0)
            .Take(10)
            .ToList();

        var lines = new List<string>
        {
            "# 📊 VulnRadar Weekly Summary", "",
            $"**Week of {weekStart} - {weekEnd}**", "",
            "---", "",
            "## 📈 This Week's Activity", "",
            "| Metric | Count |",
            "|--------|-------|",
            $"| 🆕 New CVEs This Week | {newCvesThisWeek} |",
            $"| 📊 Total CVEs Tracked | {total} |",
            $"| 🚨 Critical (Exploit + Watchlist) | {criticalCount} |",
            $"| ⚠️ In CISA KEV | {kevCount} |",
            $"| 🔥 Exploit Intel Available | {patchCount} |", "",
            "---", "",
            "## 🔴 Top 10 Critical Findings", "",
            "| CVE ID | EPSS | CVSS | KEV | Exploit | Description |",
            "|--------|------|------|-----|---------|-------------|",
        };

        foreach (var item in criticalItems)
        {
            var cveId = item.CveId;
            var desc = (item.Description.Length > 50 ? item.Description[..50] : item.Description)
                .Replace("|", "\\|").Replace("\n", " ");
            var kev = item.ActiveThreat ? "🔴" : "⚪";
            var patch = item.InPatchthis ? "🟠" : "⚪";
            lines.Add($"| [{cveId}](https://www.cve.org/CVERecord?id={cveId}) | " +
                $"{CveParsers.FormatEpss(item.ProbabilityScore)} | " +
                $"{CveParsers.FormatCvss(item.CvssScore)} | {kev} | {patch} | {desc}... |");
        }

        lines.AddRange(new[]
        {
            "", "---", "",
            "## 📋 Quick Actions", "",
            "1. **Review open critical issues** - prioritize by EPSS score",
            "2. **Check for stale issues** - close resolved CVEs",
            "3. **Update watchlist** if you've added new tech to your stack", "",
            "---",
            $"_Generated by [VulnRadar](https://github.com/ALange/VulnRadar) (C# Edition) | {now:yyyy-MM-dd HH:mm} UTC_",
        });

        var body = string.Join("\n", lines);
        var title = $"[VulnRadar] 📊 Weekly Summary - {weekStart} to {weekEnd}";
        CreateIssue(title, body, new List<string> { "vulnradar", "weekly-summary" });
        Console.WriteLine($"Created weekly summary issue: {title}");
    }

    /// <summary>Create issues and escalation comments for all candidates.</summary>
    public (int Created, int Escalated) SendAll(
        List<RadarItem> candidates,
        Dictionary<string, (RadarItem Item, List<Change> Changes)> changesByCve,
        bool dryRun = false)
    {
        var existing = LoadExistingCves();
        var issueMap = LoadIssueMap();
        var created = 0;
        var escalated = 0;

        var escalationTypes = new HashSet<string> { "NEW_KEV", "NEW_PATCHTHIS" };

        foreach (var (cveId, (it, itemChanges)) in changesByCve)
        {
            var escalationChanges = itemChanges.Where(c => escalationTypes.Contains(c.ChangeType)).ToList();
            if (escalationChanges.Count > 0 && issueMap.TryGetValue(cveId, out var issueNum))
            {
                foreach (var change in escalationChanges)
                {
                    var commentBody = FormatEscalationComment(change, it);
                    if (dryRun)
                    {
                        Console.WriteLine($"DRY RUN: would add escalation comment to #{issueNum} for {cveId}: {change.ChangeType}");
                        escalated++;
                        continue;
                    }
                    try
                    {
                        AddComment(issueNum, commentBody);
                        Console.WriteLine($"Added escalation comment to #{issueNum} for {cveId}: {change.ChangeType}");
                        escalated++;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to add comment to #{issueNum}: {ex.Message}");
                    }
                }
            }
        }

        foreach (var it in candidates)
        {
            if (created >= MaxAlerts) break;
            var cveId = it.CveId.Trim().ToUpperInvariant();
            if (!cveId.StartsWith("CVE-")) continue;

            var itemChanges = changesByCve.TryGetValue(cveId, out var cv) ? cv.Changes : new List<Change>();
            if (existing.Contains(cveId)) continue;

            var priority = it.IsCritical ? "CRITICAL" : "ALERT";
            var title = $"[VulnRadar] {priority}: {cveId}";
            var body = FormatIssueBody(it, itemChanges);
            var labels = new List<string> { "vulnradar", "alert" };
            if (it.IsCritical) labels.Add("critical");
            if (it.ActiveThreat) labels.Add("kev");
            labels.AddRange(ExtractDynamicLabels(it));
            var severityLabel = ExtractSeverityLabel(it);
            if (severityLabel != null) labels.Add(severityLabel);

            if (dryRun)
            {
                Console.WriteLine($"DRY RUN: would create issue: {title} (labels: {string.Join(", ", labels)})");
                created++;
                continue;
            }

            try
            {
                CreateIssue(title, body, labels);
                Console.WriteLine($"Created issue for {cveId}");
                existing.Add(cveId);
                created++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to create issue for {cveId}: {ex.Message}");
                break;
            }
        }

        Console.WriteLine($"Done. Created {created} GitHub issues, added {escalated} escalation comments.");
        return (created, escalated);
    }
}
