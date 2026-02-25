using System.Text.Json;
using VulnRadar.Parsers;

namespace VulnRadar.Tests;

public class CveParsersTests
{
    [Theory]
    [InlineData("Hello World", "hello world")]
    [InlineData("  APACHE  ", "apache")]
    [InlineData("Microsoft   Windows", "microsoft windows")]
    [InlineData(null, "")]
    [InlineData("", "")]
    public void Norm_NormalizesCorrectly(string? input, string expected)
    {
        Assert.Equal(expected, CveParsers.Norm(input));
    }

    [Fact]
    public void PickBestDescription_ReturnsEnglish()
    {
        var json = """
        {
            "descriptions": [
                {"lang": "es", "value": "Spanish description"},
                {"lang": "en", "value": "English description"},
                {"lang": "fr", "value": "French description"}
            ]
        }
        """;
        var el = JsonDocument.Parse(json).RootElement;
        Assert.Equal("English description", CveParsers.PickBestDescription(el));
    }

    [Fact]
    public void PickBestDescription_FallsBackToFirst()
    {
        var json = """
        {
            "descriptions": [
                {"lang": "es", "value": "Spanish description"}
            ]
        }
        """;
        var el = JsonDocument.Parse(json).RootElement;
        Assert.Equal("Spanish description", CveParsers.PickBestDescription(el));
    }

    [Fact]
    public void PickBestDescription_ReturnsEmptyWhenNone()
    {
        var json = """{"descriptions": []}""";
        var el = JsonDocument.Parse(json).RootElement;
        Assert.Equal("", CveParsers.PickBestDescription(el));
    }

    [Fact]
    public void ExtractCvss_ExtractsV31Score()
    {
        var json = """
        {
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                }
            ]
        }
        """;
        var el = JsonDocument.Parse(json).RootElement;
        var (score, severity, vector) = CveParsers.ExtractCvss(el);
        Assert.Equal(9.8, score);
        Assert.Equal("CRITICAL", severity);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", vector);
    }

    [Fact]
    public void ExtractCvss_ReturnsNullWhenNoMetrics()
    {
        var json = """{}""";
        var el = JsonDocument.Parse(json).RootElement;
        var (score, severity, vector) = CveParsers.ExtractCvss(el);
        Assert.Null(score);
        Assert.Null(severity);
        Assert.Null(vector);
    }

    [Fact]
    public void MatchesWatchlist_MatchesVendor()
    {
        var vendors = new HashSet<string> { "microsoft" };
        var products = new HashSet<string>();
        Assert.True(CveParsers.MatchesWatchlist("Microsoft Corporation", "", vendors, products));
    }

    [Fact]
    public void MatchesWatchlist_MatchesProduct()
    {
        var vendors = new HashSet<string>();
        var products = new HashSet<string> { "log4j" };
        Assert.True(CveParsers.MatchesWatchlist("", "Apache Log4j", vendors, products));
    }

    [Fact]
    public void MatchesWatchlist_NoMatch()
    {
        var vendors = new HashSet<string> { "google" };
        var products = new HashSet<string> { "chrome" };
        Assert.False(CveParsers.MatchesWatchlist("microsoft", "windows", vendors, products));
    }

    [Fact]
    public void MatchesWatchlist_EmptyWatchlist()
    {
        Assert.False(CveParsers.MatchesWatchlist("microsoft", "windows",
            new HashSet<string>(), new HashSet<string>()));
    }

    [Fact]
    public void CveYearAndNum_ParsesValid()
    {
        var result = CveParsers.CveYearAndNum("CVE-2024-12345");
        Assert.NotNull(result);
        Assert.Equal(2024, result.Value.Year);
        Assert.Equal(12345, result.Value.Num);
    }

    [Theory]
    [InlineData("CVE-INVALID")]
    [InlineData("NOT-A-CVE")]
    [InlineData("")]
    [InlineData(null)]
    public void CveYearAndNum_ReturnsNullForInvalid(string? input)
    {
        Assert.Null(CveParsers.CveYearAndNum(input));
    }

    [Fact]
    public void ParseCveJsonData_ParsesValidRecord()
    {
        var json = """
        {
            "cveMetadata": { "cveId": "CVE-2024-12345" },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "AV:N"}}
                    ],
                    "affected": [
                        {"vendor": "Test Vendor", "product": "Test Product"}
                    ]
                }
            }
        }
        """;
        var el = JsonDocument.Parse(json).RootElement;
        var result = CveParsers.ParseCveJsonData(el);

        Assert.NotNull(result);
        Assert.Equal("CVE-2024-12345", result.CveId);
        Assert.Equal("Test vulnerability", result.Description);
        Assert.Equal(7.5, result.CvssScore);
        Assert.Equal("HIGH", result.CvssSeverity);
        Assert.Single(result.Affected);
        Assert.Equal("test vendor", result.Affected[0].Vendor);
    }

    [Fact]
    public void ParseCveJsonData_ReturnsNullForInvalidId()
    {
        var json = """{"cveMetadata": {"cveId": "INVALID"}}""";
        var el = JsonDocument.Parse(json).RootElement;
        Assert.Null(CveParsers.ParseCveJsonData(el));
    }

    [Theory]
    [InlineData(true, false, false, 0.8, 9.0, "CRITICAL")]
    [InlineData(false, true, false, 0.3, 5.0, "KEV")]
    [InlineData(false, false, false, 0.75, 5.0, "High EPSS")]
    [InlineData(false, false, false, 0.3, 9.5, "Critical CVSS")]
    [InlineData(false, false, false, 0.3, 5.0, "Other")]
    public void RiskBucket_ClassifiesCorrectly(
        bool isCritical, bool activeThreat, bool _, double epss, double cvss, string expected)
    {
        var item = new RadarItem
        {
            IsCritical = isCritical,
            ActiveThreat = activeThreat,
            ProbabilityScore = epss,
            CvssScore = cvss,
        };
        Assert.Equal(expected, CveParsers.RiskBucket(item));
    }

    [Fact]
    public void RiskSortKey_CriticalItemsRankHigher()
    {
        var critical = new RadarItem { IsCritical = true, ProbabilityScore = 0.5, CvssScore = 7.0 };
        var kev = new RadarItem { IsCritical = false, ActiveThreat = true, ProbabilityScore = 0.9, CvssScore = 9.0 };
        Assert.True(CveParsers.RiskSortKey(critical) > CveParsers.RiskSortKey(kev));
    }

    [Theory]
    [InlineData("exact", "exact", 1.0)]
    [InlineData("test", "test string", 0.8)]
    [InlineData("", "anything", 0.0)]
    public void FuzzyScore_ComputesCorrectly(string query, string target, double minExpected)
    {
        var score = CveParsers.FuzzyScore(query, target);
        Assert.True(score >= minExpected - 0.01, $"Expected score >= {minExpected} but got {score}");
    }

    [Theory]
    [InlineData(0.5, "50.0%")]
    [InlineData(0.123, "12.3%")]
    [InlineData(null, "N/A")]
    public void FormatEpss_FormatsCorrectly(double? epss, string expected)
    {
        Assert.Equal(expected, CveParsers.FormatEpss(epss));
    }

    [Theory]
    [InlineData(9.8, "9.8")]
    [InlineData(7.5, "7.5")]
    [InlineData(null, "N/A")]
    public void FormatCvss_FormatsCorrectly(double? cvss, string expected)
    {
        Assert.Equal(expected, CveParsers.FormatCvss(cvss));
    }
}
