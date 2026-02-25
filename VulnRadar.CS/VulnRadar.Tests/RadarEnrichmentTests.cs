using VulnRadar.Enrichment;
using VulnRadar.Parsers;
using System.Text.Json;

namespace VulnRadar.Tests;

public class RadarEnrichmentTests
{
    [Fact]
    public void YearsToProcess_ReturnsCorrectRange()
    {
        var years = RadarEnrichment.YearsToProcess(2022, 2024);
        Assert.Equal(new[] { 2022, 2023, 2024 }, years);
    }

    [Fact]
    public void YearsToProcess_EmptyWhenMaxLessThanMin()
    {
        var years = RadarEnrichment.YearsToProcess(2024, 2022);
        Assert.Empty(years);
    }

    [Fact]
    public void YearsToProcess_NullMaxUsesCurrentYear()
    {
        var currentYear = DateTime.UtcNow.Year;
        var years = RadarEnrichment.YearsToProcess(currentYear, null);
        Assert.Equal(new[] { currentYear }, years);
    }

    [Fact]
    public void WriteAndLoadRadarData_RoundTrips()
    {
        var tmpFile = Path.GetTempFileName() + ".json";
        try
        {
            var items = new List<RadarItem>
            {
                new RadarItem
                {
                    CveId = "CVE-2024-12345",
                    Description = "Test vulnerability",
                    CvssScore = 9.8,
                    IsCritical = true,
                    ActiveThreat = true,
                    ProbabilityScore = 0.85,
                },
            };

            RadarEnrichment.WriteRadarData(tmpFile, items);
            Assert.True(File.Exists(tmpFile));

            var loaded = RadarEnrichment.LoadRadarData(tmpFile);
            Assert.Single(loaded);
            Assert.Equal("CVE-2024-12345", loaded[0].CveId);
            Assert.Equal(9.8, loaded[0].CvssScore);
            Assert.True(loaded[0].IsCritical);
            Assert.Equal(0.85, loaded[0].ProbabilityScore);
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }

    [Fact]
    public void LoadRadarData_ReturnsEmptyForMissingFile()
    {
        var result = RadarEnrichment.LoadRadarData("/nonexistent/path.json");
        Assert.Empty(result);
    }

    [Fact]
    public void NowUtcIso_ReturnsValidIso8601()
    {
        var result = RadarEnrichment.NowUtcIso();
        Assert.True(DateTime.TryParse(result, out _));
    }

    [Fact]
    public void BuildRadarData_FiltersNonWatchlistNonKev()
    {
        // Create a temp directory with a CVE JSON file
        var tmpDir = Path.Combine(Path.GetTempPath(), $"vr_test_{Guid.NewGuid():N}");
        var cvesDir = Path.Combine(tmpDir, "cves", "2024", "0xxx");
        Directory.CreateDirectory(cvesDir);

        var cveJson = """
        {
            "cveMetadata": {"cveId": "CVE-2024-00001"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test CVE"}],
                    "affected": [{"vendor": "TestVendor", "product": "TestProduct"}]
                }
            }
        }
        """;
        File.WriteAllText(Path.Combine(cvesDir, "CVE-2024-00001.json"), cveJson);

        try
        {
            // Non-matching watchlist, no KEV — should return empty
            var items = RadarEnrichment.BuildRadarData(
                extractedDir: tmpDir,
                wlVendors: new HashSet<string> { "google" },
                wlProducts: new HashSet<string> { "chrome" },
                kevByCve: new Dictionary<string, JsonElement>(),
                epssByCve: new Dictionary<string, double>(),
                patchthisCves: new HashSet<string>(),
                nvdByCve: new Dictionary<string, VulnRadar.Downloaders.NvdItemData>(),
                minYear: 2024,
                maxYear: 2024,
                includeKevOutsideWindow: false);

            Assert.Empty(items);
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public void BuildRadarData_IncludesWatchlistMatch()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"vr_test_{Guid.NewGuid():N}");
        var cvesDir = Path.Combine(tmpDir, "cves", "2024", "0xxx");
        Directory.CreateDirectory(cvesDir);

        var cveJson = """
        {
            "cveMetadata": {"cveId": "CVE-2024-00002"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test CVE"}],
                    "affected": [{"vendor": "TestVendor", "product": "TestProduct"}]
                }
            }
        }
        """;
        File.WriteAllText(Path.Combine(cvesDir, "CVE-2024-00002.json"), cveJson);

        try
        {
            var items = RadarEnrichment.BuildRadarData(
                extractedDir: tmpDir,
                wlVendors: new HashSet<string> { "testvendor" },
                wlProducts: new HashSet<string>(),
                kevByCve: new Dictionary<string, JsonElement>(),
                epssByCve: new Dictionary<string, double>(),
                patchthisCves: new HashSet<string>(),
                nvdByCve: new Dictionary<string, VulnRadar.Downloaders.NvdItemData>(),
                minYear: 2024,
                maxYear: 2024,
                includeKevOutsideWindow: false);

            Assert.Single(items);
            Assert.Equal("CVE-2024-00002", items[0].CveId);
            Assert.True(items[0].WatchlistHit);
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public void BuildRadarData_MarksCriticalWhenPatchthisAndWatchlist()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"vr_test_{Guid.NewGuid():N}");
        var cvesDir = Path.Combine(tmpDir, "cves", "2024", "0xxx");
        Directory.CreateDirectory(cvesDir);

        var cveJson = """
        {
            "cveMetadata": {"cveId": "CVE-2024-00003"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Critical CVE"}],
                    "affected": [{"vendor": "TestVendor", "product": "TestProduct"}]
                }
            }
        }
        """;
        File.WriteAllText(Path.Combine(cvesDir, "CVE-2024-00003.json"), cveJson);

        try
        {
            var items = RadarEnrichment.BuildRadarData(
                extractedDir: tmpDir,
                wlVendors: new HashSet<string> { "testvendor" },
                wlProducts: new HashSet<string>(),
                kevByCve: new Dictionary<string, JsonElement>(),
                epssByCve: new Dictionary<string, double>(),
                patchthisCves: new HashSet<string> { "CVE-2024-00003" },
                nvdByCve: new Dictionary<string, VulnRadar.Downloaders.NvdItemData>(),
                minYear: 2024,
                maxYear: 2024,
                includeKevOutsideWindow: false);

            Assert.Single(items);
            Assert.True(items[0].IsCritical);
            Assert.True(items[0].InPatchthis);
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public void FindCvesRoot_FindsCvesDirectory()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"vr_test_{Guid.NewGuid():N}");
        var cvesDir = Path.Combine(tmpDir, "cves");
        Directory.CreateDirectory(cvesDir);

        try
        {
            var result = RadarEnrichment.FindCvesRoot(tmpDir);
            Assert.Equal(cvesDir, result);
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }

    [Fact]
    public void FindCvesRoot_ReturnsExtractedDirWhenNoCves()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"vr_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            var result = RadarEnrichment.FindCvesRoot(tmpDir);
            Assert.Equal(tmpDir, result);
        }
        finally
        {
            Directory.Delete(tmpDir, recursive: true);
        }
    }
}
