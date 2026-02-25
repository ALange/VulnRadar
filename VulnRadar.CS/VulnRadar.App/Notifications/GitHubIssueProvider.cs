using System.Net.Http.Json;
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
        _session.PostAsJsonAsync(url, new { body }).GetAwaiter().GetResult()
            .EnsureSuccessStatusCode();
    }

    private bool IssuesEnabled()
    {
        try
        {
            var r = _session.GetAsync($"https://api.github.com/repos/{_repo}").GetAwaiter().GetResult();
            if (r.IsSuccessStatusCode)
            {
                var text = r.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var doc = JsonDocument.Parse(text).RootElement;
                if (doc.TryGetProperty("has_issues", out var hi))
                    return hi.GetBoolean();
            }
        }
        catch { /* ignore */ }
        return true;
    }

    // ─── GitHub Projects v2 ───────────────────────────────────────────────────

    /// <summary>Parse a GitHub Projects URL into owner/type/number.</summary>
    public static (string Owner, string Type, int Number)? ParseProjectUrl(string projectUrl)
    {
        var userMatch = Regex.Match(projectUrl,
            @"https?://github\.com/users/([^/]+)/projects/(\d+)");
        if (userMatch.Success)
            return (userMatch.Groups[1].Value, "user", int.Parse(userMatch.Groups[2].Value));

        var orgMatch = Regex.Match(projectUrl,
            @"https?://github\.com/orgs/([^/]+)/projects/(\d+)");
        if (orgMatch.Success)
            return (orgMatch.Groups[1].Value, "organization", int.Parse(orgMatch.Groups[2].Value));

        return null;
    }

    private string? ResolveProjectId()
    {
        if (string.IsNullOrEmpty(_projectUrl)) return null;
        if (_projectId != null) return _projectId;

        var parsed = ParseProjectUrl(_projectUrl);
        if (parsed == null)
        {
            Console.WriteLine($"⚠️ Invalid project URL format: {_projectUrl}");
            return null;
        }

        var (owner, ownerType, number) = parsed.Value;

        string query;
        if (ownerType == "user")
            query = "query($owner: String!, $number: Int!) { user(login: $owner) { projectV2(number: $number) { id title } } }";
        else
            query = "query($owner: String!, $number: Int!) { organization(login: $owner) { projectV2(number: $number) { id title } } }";

        var payload = new { query, variables = new { owner, number } };
        var response = _session.PostAsJsonAsync("https://api.github.com/graphql", payload)
            .GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();

        var text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        var doc = JsonDocument.Parse(text).RootElement;

        if (doc.TryGetProperty("errors", out var errs))
        {
            Console.WriteLine($"GraphQL error getting project: {errs}");
            return null;
        }

        if (!doc.TryGetProperty("data", out var data)) return null;
        var key = ownerType == "user" ? "user" : "organization";
        if (!data.TryGetProperty(key, out var ownerEl)) return null;
        if (!ownerEl.TryGetProperty("projectV2", out var project)) return null;
        if (!project.TryGetProperty("id", out var idEl)) return null;
        _projectId = idEl.GetString();
        return _projectId;
    }

    private bool AddToProject(string contentNodeId)
    {
        var projectId = ResolveProjectId();
        if (projectId == null) return false;

        const string mutation = "mutation($projectId: ID!, $contentId: ID!) { addProjectV2ItemByContentId(input: {projectId: $projectId, contentId: $contentId}) { item { id } } }";
        var payload = new { query = mutation, variables = new { projectId, contentId = contentNodeId } };
        try
        {
            var response = _session.PostAsJsonAsync("https://api.github.com/graphql", payload)
                .GetAwaiter().GetResult();
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    // ─── Issue body formatting ────────────────────────────────────────────────

    /// <summary>Generate a rich GitHub issue body for a CVE, matching the Python format.</summary>
    public static string FormatIssueBody(RadarItem item, List<Change>? changes = null)
    {
        var cveId = item.CveId;
        var desc = (item.Description ?? "").Trim();
        var epss = item.ProbabilityScore;
        var cvss = item.CvssScore;
        var kev = item.ActiveThreat;
        var patch = item.InPatchthis;
        var watch = item.WatchlistHit;

        var kevObj = item.Kev;
        var kevDue = kevObj?.DueDate ?? "";
        var kevVendor = kevObj?.VendorProject ?? "";
        var kevProduct = kevObj?.Product ?? "";
        var kevName = kevObj?.VulnerabilityName ?? "";

        // Derive vendor/product: use first affected pair if available, fall back to KEV
        var firstAffected = item.Affected.FirstOrDefault(a =>
            !string.IsNullOrEmpty(a.Vendor) || !string.IsNullOrEmpty(a.Product));
        var vendor = firstAffected?.Vendor ?? "";
        var product = firstAffected?.Product ?? "";

        static string Fmt(double? x, int digits) => x.HasValue
            ? x.Value.ToString($"F{digits}", System.Globalization.CultureInfo.InvariantCulture) : "N/A";
        static string FmtPct(double? x) => x.HasValue
            ? $"{x.Value * 100.0:F1}%" : "N/A";

        var lines = new List<string>();

        if (changes != null && changes.Count > 0)
        {
            lines.Add("## 🔔 Alert Reason");
            lines.Add("");
            foreach (var c in changes)
                lines.Add($"> {c}");
            lines.Add("");
        }

        lines.Add("## Overview");
        lines.Add("");
        lines.Add("| Field | Value |");
        lines.Add("|-------|-------|");
        lines.Add($"| **CVE ID** | [{cveId}](https://www.cve.org/CVERecord?id={cveId}) |");
        lines.Add($"| **Vendor** | {(!string.IsNullOrEmpty(vendor) ? vendor : !string.IsNullOrEmpty(kevVendor) ? kevVendor : "Unknown")} |");
        lines.Add($"| **Product** | {(!string.IsNullOrEmpty(product) ? product : !string.IsNullOrEmpty(kevProduct) ? kevProduct : "Unknown")} |");
        lines.Add($"| **CVSS Score** | {Fmt(cvss, 1)} |");
        lines.Add($"| **EPSS Score** | {FmtPct(epss)} |");
        lines.Add("");

        lines.Add("## ⚠️ Threat Signals");
        lines.Add("");
        lines.Add("| Signal | Status |");
        lines.Add("|--------|--------|");
        lines.Add($"| CISA KEV | {(kev ? "🔴 **YES** - Known Exploited" : "⚪ No")} |");
        lines.Add($"| Exploit Intel | {(patch ? "🟠 **YES** - PoC Available" : "⚪ No")} |");
        lines.Add($"| Watchlist Match | {(watch ? "🟡 **YES**" : "⚪ No")} |");
        if (!string.IsNullOrEmpty(kevDue))
            lines.Add($"| KEV Remediation Due | **{kevDue}** |");
        lines.Add("");

        lines.Add("## 📝 Description");
        lines.Add("");
        if (!string.IsNullOrEmpty(kevName))
        {
            lines.Add($"**{kevName}**");
            lines.Add("");
        }
        lines.Add(!string.IsNullOrEmpty(desc) ? desc : "_No description available._");
        lines.Add("");

        if (item.Affected.Count > 0)
        {
            lines.Add("## 📦 Affected Components");
            lines.Add("");
            foreach (var aff in item.Affected.Take(10))
            {
                var parts = new List<string>();
                if (!string.IsNullOrEmpty(aff.Vendor)) parts.Add($"vendor: {aff.Vendor}");
                if (!string.IsNullOrEmpty(aff.Product)) parts.Add($"product: {aff.Product}");
                if (parts.Count > 0) lines.Add($"- {string.Join(", ", parts)}");
            }
            if (item.Affected.Count > 10)
                lines.Add($"- _...and {item.Affected.Count - 10} more_");
            lines.Add("");
        }

        lines.Add("## 🔗 References");
        lines.Add("");
        lines.Add($"- [CVE.org Record](https://www.cve.org/CVERecord?id={cveId})");
        lines.Add($"- [NVD Entry](https://nvd.nist.gov/vuln/detail/{cveId})");
        if (kev)
            lines.Add("- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)");
        lines.Add("");
        lines.Add("---");
        lines.Add("_Generated by [VulnRadar](https://github.com/ALange/VulnRadar)_");

        return string.Join("\n", lines);
    }

    /// <summary>Generate a comment body for escalation events, matching the Python format.</summary>
    public static string FormatEscalationComment(Change change, RadarItem item)
    {
        var cveId = change.CveId;
        var lines = new List<string> { "## ⚠️ Status Update", "" };

        if (change.ChangeType == "NEW_KEV")
        {
            lines.AddRange(new[]
            {
                $"🚨 **{cveId} has been added to CISA KEV!**", "",
                "This vulnerability is now confirmed to be actively exploited in the wild.", "",
            });
            var kev = item.Kev;
            if (kev != null)
            {
                if (!string.IsNullOrEmpty(kev.DueDate))
                    lines.Add($"**Remediation Due Date:** {kev.DueDate}");
                lines.Add("");
            }
            lines.AddRange(new[]
            {
                "**Action Required:** Prioritize patching immediately.", "",
                "[View CISA KEV Entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
            });
        }
        else if (change.ChangeType == "NEW_PATCHTHIS")
        {
            lines.AddRange(new[]
            {
                $"🔥 **{cveId} now has Exploit Intel (PoC Available)!**", "",
                "A proof-of-concept or exploit code has been identified for this vulnerability.", "",
                "**Action Required:** Increase priority - exploitation is now easier.",
            });
        }
        else
        {
            lines.AddRange(new[]
            {
                $"📢 **{cveId} status has changed**", "",
                $"Change type: {change.ChangeType}",
            });
        }

        lines.AddRange(new[]
        {
            "", "---",
            "_Escalation comment by [VulnRadar](https://github.com/ALange/VulnRadar)_",
        });
        return string.Join("\n", lines);
    }

    /// <summary>Extract vendor/product labels from matched_terms, matching the Python format.</summary>
    public static List<string> ExtractDynamicLabels(RadarItem item, int maxLabels = 3)
    {
        var labels = new List<string>();
        foreach (var term in item.MatchedTerms)
        {
            if (string.IsNullOrWhiteSpace(term)) continue;
            var clean = term.ToLowerInvariant().Trim().Replace(" ", "-");
            if (clean.Length <= 50 && !labels.Contains(clean))
                labels.Add(clean);
            if (labels.Count >= maxLabels) break;
        }
        return labels;
    }

    /// <summary>Extract severity label based on CVSS score, using colon format like Python.</summary>
    public static string? ExtractSeverityLabel(RadarItem item)
    {
        var cvss = item.CvssScore;
        if (!cvss.HasValue) return null;
        return cvss.Value switch
        {
            >= 9.0 => "severity:critical",
            >= 7.0 => "severity:high",
            >= 4.0 => "severity:medium",
            _ => "severity:low",
        };
    }

    // ─── NotificationProvider interface methods ───────────────────────────────

    public override void SendAlert(RadarItem item, List<Change>? changes = null)
    {
        // Individual alerts are handled via SendAll
    }

    public override void SendSummary(
        List<RadarItem> items,
        string repo,
        Dictionary<string, (RadarItem Item, List<Change> Changes)>? changesByCve = null)
    {
        // Weekly summary is handled via CreateWeeklySummary
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

        foreach (var it in sorted.Take(20))
        {
            var cveId = it.CveId;
            var rawDesc = it.Description ?? "";
            var desc = (rawDesc.Length > 60 ? rawDesc[..60] : rawDesc)
                .Replace("|", "\\|").Replace("\n", " ");
            var kevMark = it.ActiveThreat ? "🔴" : "⚪";
            var patchMark = it.InPatchthis ? "🟠" : "⚪";
            lines.Add($"| [{cveId}](https://www.cve.org/CVERecord?id={cveId}) | " +
                $"{CveParsers.FormatEpss(it.ProbabilityScore)} | " +
                $"{CveParsers.FormatCvss(it.CvssScore)} | {kevMark} | {patchMark} | {desc}... |");
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
            "_Generated by [VulnRadar](https://github.com/ALange/VulnRadar) - First Run Baseline_",
        });

        var body = string.Join("\n", lines);
        var title = $"[VulnRadar] 🚀 Baseline Established - {criticalCount} Critical Findings";
        CreateIssue(title, body, new List<string> { "vulnradar", "baseline" });
        Console.WriteLine($"Created baseline summary issue with {criticalCount} critical findings");
    }

    /// <summary>Create a weekly summary issue, matching the Python format.</summary>
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
                if (DateTime.TryParse(firstSeen, out var fsdt) && fsdt >= weekAgo)
                    newCvesThisWeek++;
            }
        }

        var criticalItems = items
            .Where(i => i.IsCritical)
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

        foreach (var it in criticalItems)
        {
            var cveId = it.CveId;
            var rawDesc = it.Description ?? "";
            var desc = (rawDesc.Length > 50 ? rawDesc[..50] : rawDesc)
                .Replace("|", "\\|").Replace("\n", " ");
            var kevMark = it.ActiveThreat ? "🔴" : "⚪";
            var patchMark = it.InPatchthis ? "🟠" : "⚪";
            lines.Add($"| [{cveId}](https://www.cve.org/CVERecord?id={cveId}) | " +
                $"{CveParsers.FormatEpss(it.ProbabilityScore)} | " +
                $"{CveParsers.FormatCvss(it.CvssScore)} | {kevMark} | {patchMark} | {desc}... |");
        }

        lines.AddRange(new[]
        {
            "", "---", "",
            "## 📋 Quick Actions", "",
            "1. **Review open critical issues** - prioritize by EPSS score",
            "2. **Check for stale issues** - close resolved CVEs",
            "3. **Update watchlist** if you've added new tech to your stack", "",
            "---",
            $"_Generated by [VulnRadar](https://github.com/ALange/VulnRadar) | {now:yyyy-MM-dd HH:mm} UTC_",
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
        if (!IssuesEnabled())
        {
            Console.WriteLine("GitHub Issues are not enabled on this repository.");
            return (0, 0);
        }

        var existing = LoadExistingCves();
        var issueMap = LoadIssueMap();
        var created = 0;
        var escalated = 0;

        var escalationTypes = new HashSet<string> { "NEW_KEV", "NEW_PATCHTHIS" };

        // Handle escalation comments for existing issues
        foreach (var (cveId, (it, itemChanges)) in changesByCve)
        {
            var escalationChanges = itemChanges
                .Where(c => escalationTypes.Contains(c.ChangeType))
                .ToList();
            if (escalationChanges.Count == 0 || !issueMap.TryGetValue(cveId, out var issueNum))
                continue;

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

        // Create new issues
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
                var issueData = CreateIssue(title, body, labels);
                Console.WriteLine($"Created issue for {cveId}");
                existing.Add(cveId);
                created++;

                // Add to GitHub Projects v2 if configured
                if (!string.IsNullOrEmpty(_projectUrl) && issueData.HasValue)
                {
                    var nodeId = issueData.Value.TryGetProperty("node_id", out var ni)
                        ? ni.GetString() : null;
                    if (!string.IsNullOrEmpty(nodeId))
                    {
                        if (AddToProject(nodeId!))
                            Console.WriteLine("  → Added to project board");
                    }
                }
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
