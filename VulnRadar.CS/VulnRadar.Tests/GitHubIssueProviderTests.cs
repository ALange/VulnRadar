using VulnRadar.Notifications;
using VulnRadar.Parsers;
using VulnRadar.State;
using Xunit;

namespace VulnRadar.Tests;

public class GitHubIssueProviderTests
{
    // ─── ExtractSeverityLabel ─────────────────────────────────────────────────

    [Theory]
    [InlineData(9.8, "severity:critical")]
    [InlineData(9.0, "severity:critical")]
    [InlineData(8.9, "severity:high")]
    [InlineData(7.0, "severity:high")]
    [InlineData(6.9, "severity:medium")]
    [InlineData(4.0, "severity:medium")]
    [InlineData(3.9, "severity:low")]
    [InlineData(0.0, "severity:low")]
    public void ExtractSeverityLabel_ReturnsColonFormat(double cvss, string expected)
    {
        var item = new RadarItem { CvssScore = cvss };
        Assert.Equal(expected, GitHubIssueProvider.ExtractSeverityLabel(item));
    }

    [Fact]
    public void ExtractSeverityLabel_NullCvss_ReturnsNull()
    {
        var item = new RadarItem { CvssScore = null };
        Assert.Null(GitHubIssueProvider.ExtractSeverityLabel(item));
    }

    // ─── ExtractDynamicLabels ─────────────────────────────────────────────────

    [Fact]
    public void ExtractDynamicLabels_ExtractsFromMatchedTerms()
    {
        var item = new RadarItem
        {
            MatchedTerms = new List<string> { "vendor:apache", "product:log4j" }
        };
        var labels = GitHubIssueProvider.ExtractDynamicLabels(item);
        Assert.Equal(new[] { "vendor:apache", "product:log4j" }, labels);
    }

    [Fact]
    public void ExtractDynamicLabels_RespectsMaxLabels()
    {
        var item = new RadarItem
        {
            MatchedTerms = new List<string>
                { "vendor:a", "vendor:b", "product:c", "product:d" }
        };
        var labels = GitHubIssueProvider.ExtractDynamicLabels(item, maxLabels: 3);
        Assert.Equal(3, labels.Count);
    }

    [Fact]
    public void ExtractDynamicLabels_ReplacesSpacesWithDashes()
    {
        var item = new RadarItem
        {
            MatchedTerms = new List<string> { "vendor:my vendor" }
        };
        var labels = GitHubIssueProvider.ExtractDynamicLabels(item);
        Assert.Equal("vendor:my-vendor", labels[0]);
    }

    [Fact]
    public void ExtractDynamicLabels_DeduplicatesLabels()
    {
        var item = new RadarItem
        {
            MatchedTerms = new List<string> { "vendor:apache", "vendor:apache" }
        };
        var labels = GitHubIssueProvider.ExtractDynamicLabels(item);
        Assert.Single(labels);
    }

    [Fact]
    public void ExtractDynamicLabels_EmptyMatchedTerms_ReturnsEmptyList()
    {
        var item = new RadarItem { MatchedTerms = new List<string>() };
        var labels = GitHubIssueProvider.ExtractDynamicLabels(item);
        Assert.Empty(labels);
    }

    // ─── FormatIssueBody ──────────────────────────────────────────────────────

    [Fact]
    public void FormatIssueBody_ContainsOverviewSection()
    {
        var item = new RadarItem
        {
            CveId = "CVE-2024-12345",
            Description = "Test vulnerability description.",
            CvssScore = 9.8,
            ProbabilityScore = 0.5,
        };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("## Overview", body);
        Assert.Contains("CVE-2024-12345", body);
        Assert.Contains("https://www.cve.org/CVERecord?id=CVE-2024-12345", body);
        Assert.Contains("9.8", body);
        Assert.Contains("50.0%", body);
    }

    [Fact]
    public void FormatIssueBody_ContainsThreatSignalsSection()
    {
        var item = new RadarItem
        {
            CveId = "CVE-2024-11111",
            ActiveThreat = true,
            InPatchthis = true,
            WatchlistHit = true,
        };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("## ⚠️ Threat Signals", body);
        Assert.Contains("🔴 **YES** - Known Exploited", body);
        Assert.Contains("🟠 **YES** - PoC Available", body);
        Assert.Contains("🟡 **YES**", body);
    }

    [Fact]
    public void FormatIssueBody_ContainsDescriptionSection()
    {
        var item = new RadarItem
        {
            CveId = "CVE-2024-22222",
            Description = "This is a test description.",
        };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("## 📝 Description", body);
        Assert.Contains("This is a test description.", body);
    }

    [Fact]
    public void FormatIssueBody_ShowsKevName_WhenKevPresent()
    {
        var item = new RadarItem
        {
            CveId = "CVE-2024-33333",
            Kev = new KevEntry
            {
                VulnerabilityName = "Critical Log4j Vulnerability",
                DueDate = "2024-12-31",
                VendorProject = "Apache",
                Product = "Log4j",
            }
        };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("**Critical Log4j Vulnerability**", body);
        Assert.Contains("KEV Remediation Due", body);
        Assert.Contains("2024-12-31", body);
    }

    [Fact]
    public void FormatIssueBody_ShowsAlertReason_WhenChangesPresent()
    {
        var item = new RadarItem { CveId = "CVE-2024-44444" };
        var changes = new List<Change>
        {
            new Change { CveId = "CVE-2024-44444", ChangeType = "NEW_CVE" }
        };
        var body = GitHubIssueProvider.FormatIssueBody(item, changes);
        Assert.Contains("## 🔔 Alert Reason", body);
        Assert.Contains("🆕 NEW: CVE-2024-44444", body);
    }

    [Fact]
    public void FormatIssueBody_ShowsReferencesSection()
    {
        var item = new RadarItem { CveId = "CVE-2024-55555" };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("## 🔗 References", body);
        Assert.Contains("https://nvd.nist.gov/vuln/detail/CVE-2024-55555", body);
    }

    [Fact]
    public void FormatIssueBody_ShowsKevCatalogLink_WhenActiveThreat()
    {
        var item = new RadarItem { CveId = "CVE-2024-66666", ActiveThreat = true };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("CISA KEV Catalog", body);
    }

    [Fact]
    public void FormatIssueBody_UsesVendorFromKev_WhenAffectedEmpty()
    {
        var item = new RadarItem
        {
            CveId = "CVE-2024-77777",
            Kev = new KevEntry { VendorProject = "Microsoft", Product = "Windows" }
        };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("Microsoft", body);
        Assert.Contains("Windows", body);
    }

    [Fact]
    public void FormatIssueBody_ShowsAffectedComponents_WhenPresent()
    {
        var item = new RadarItem
        {
            CveId = "CVE-2024-88888",
            Affected = new List<AffectedEntryJson>
            {
                new AffectedEntryJson { Vendor = "apache", Product = "log4j" }
            }
        };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("## 📦 Affected Components", body);
        Assert.Contains("vendor: apache", body);
        Assert.Contains("product: log4j", body);
    }

    [Fact]
    public void FormatIssueBody_FooterContainsVulnRadar()
    {
        var item = new RadarItem { CveId = "CVE-2024-99999" };
        var body = GitHubIssueProvider.FormatIssueBody(item);
        Assert.Contains("Generated by [VulnRadar]", body);
    }

    // ─── FormatEscalationComment ──────────────────────────────────────────────

    [Fact]
    public void FormatEscalationComment_NewKev_MatchesPythonFormat()
    {
        var change = new Change { CveId = "CVE-2024-1111", ChangeType = "NEW_KEV" };
        var item = new RadarItem
        {
            CveId = "CVE-2024-1111",
            Kev = new KevEntry { DueDate = "2024-12-31" }
        };
        var comment = GitHubIssueProvider.FormatEscalationComment(change, item);
        Assert.Contains("## ⚠️ Status Update", comment);
        Assert.Contains("🚨 **CVE-2024-1111 has been added to CISA KEV!**", comment);
        Assert.Contains("actively exploited in the wild", comment);
        Assert.Contains("Remediation Due Date:** 2024-12-31", comment);
        Assert.Contains("Prioritize patching immediately", comment);
        Assert.Contains("Escalation comment by [VulnRadar]", comment);
    }

    [Fact]
    public void FormatEscalationComment_NewPatchthis_MatchesPythonFormat()
    {
        var change = new Change { CveId = "CVE-2024-2222", ChangeType = "NEW_PATCHTHIS" };
        var item = new RadarItem { CveId = "CVE-2024-2222" };
        var comment = GitHubIssueProvider.FormatEscalationComment(change, item);
        Assert.Contains("## ⚠️ Status Update", comment);
        Assert.Contains("🔥 **CVE-2024-2222 now has Exploit Intel (PoC Available)!**", comment);
        Assert.Contains("proof-of-concept", comment);
        Assert.Contains("Escalation comment by [VulnRadar]", comment);
    }

    [Fact]
    public void FormatEscalationComment_Other_ShowsChangeType()
    {
        var change = new Change { CveId = "CVE-2024-3333", ChangeType = "BECAME_CRITICAL" };
        var item = new RadarItem { CveId = "CVE-2024-3333" };
        var comment = GitHubIssueProvider.FormatEscalationComment(change, item);
        Assert.Contains("## ⚠️ Status Update", comment);
        Assert.Contains("📢 **CVE-2024-3333 status has changed**", comment);
        Assert.Contains("BECAME_CRITICAL", comment);
    }

    // ─── ParseProjectUrl ──────────────────────────────────────────────────────

    [Fact]
    public void ParseProjectUrl_OrgProject_ReturnsParsed()
    {
        var result = GitHubIssueProvider.ParseProjectUrl("https://github.com/orgs/MyOrg/projects/42");
        Assert.NotNull(result);
        Assert.Equal("MyOrg", result!.Value.Owner);
        Assert.Equal("organization", result.Value.Type);
        Assert.Equal(42, result.Value.Number);
    }

    [Fact]
    public void ParseProjectUrl_UserProject_ReturnsParsed()
    {
        var result = GitHubIssueProvider.ParseProjectUrl("https://github.com/users/johndoe/projects/7");
        Assert.NotNull(result);
        Assert.Equal("johndoe", result!.Value.Owner);
        Assert.Equal("user", result.Value.Type);
        Assert.Equal(7, result.Value.Number);
    }

    [Fact]
    public void ParseProjectUrl_InvalidUrl_ReturnsNull()
    {
        Assert.Null(GitHubIssueProvider.ParseProjectUrl("https://github.com/owner/repo"));
        Assert.Null(GitHubIssueProvider.ParseProjectUrl("not-a-url"));
        Assert.Null(GitHubIssueProvider.ParseProjectUrl(""));
    }
}
