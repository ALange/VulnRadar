using VulnRadar.Config;

namespace VulnRadar.Tests;

public class WatchlistConfigTests
{
    [Fact]
    public void NormalizeSet_NormalizesStrings()
    {
        var input = new[] { "Microsoft", "  APACHE  ", "log4j" };
        var result = WatchlistConfig.NormalizeSet(input);
        Assert.Contains("microsoft", result);
        Assert.Contains("apache", result);
        Assert.Contains("log4j", result);
    }

    [Fact]
    public void NormalizeSet_RemovesEmpty()
    {
        var input = new[] { "", "  ", "valid" };
        var result = WatchlistConfig.NormalizeSet(input);
        Assert.DoesNotContain("", result);
        Assert.Contains("valid", result);
    }

    [Fact]
    public void NormalizeSet_CollapsesWhitespace()
    {
        var input = new[] { "apache   log4j" };
        var result = WatchlistConfig.NormalizeSet(input);
        Assert.Contains("apache log4j", result);
    }

    [Fact]
    public void LoadWatchlist_LoadsYaml()
    {
        // Create a temp YAML file
        var tmpFile = Path.GetTempFileName() + ".yaml";
        try
        {
            File.WriteAllText(tmpFile, """
            vendors:
              - Microsoft
              - Apache
            products:
              - Log4j
              - Windows
            thresholds:
              min_cvss: 7.0
              severity_threshold: 9.0
            options:
              always_include_kev: true
            """);

            var config = WatchlistLoader.LoadWatchlist(tmpFile);
            Assert.Contains("microsoft", config.Vendors);
            Assert.Contains("apache", config.Vendors);
            Assert.Contains("log4j", config.Products);
            Assert.Contains("windows", config.Products);
            Assert.Equal(7.0, config.Thresholds.MinCvss);
            Assert.Equal(9.0, config.Thresholds.SeverityThreshold);
            Assert.True(config.Options.AlwaysIncludeKev);
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }

    [Fact]
    public void LoadWatchlist_LoadsMinimalYaml()
    {
        var tmpFile = Path.GetTempFileName() + ".yaml";
        try
        {
            File.WriteAllText(tmpFile, "vendors:\n  - test");
            var config = WatchlistLoader.LoadWatchlist(tmpFile);
            Assert.Contains("test", config.Vendors);
            Assert.Empty(config.Products);
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }

    [Fact]
    public void LoadWatchlist_EmptyFileReturnsDefaults()
    {
        var tmpFile = Path.GetTempFileName() + ".yaml";
        try
        {
            File.WriteAllText(tmpFile, "");
            var config = WatchlistLoader.LoadWatchlist(tmpFile);
            Assert.Empty(config.Vendors);
            Assert.Empty(config.Products);
        }
        finally
        {
            File.Delete(tmpFile);
        }
    }

    [Fact]
    public void FindWatchlist_ReturnsDefaultWhenNotFound()
    {
        // This will return "watchlist.yaml" as default when file doesn't exist
        // We can only verify it returns a non-empty string
        var result = WatchlistLoader.FindWatchlist();
        Assert.NotEmpty(result);
    }

    [Fact]
    public void WatchlistConfig_MergeFrom()
    {
        var main = new WatchlistConfig
        {
            Vendors = new HashSet<string> { "microsoft" },
            Products = new HashSet<string> { "windows" },
        };
        var other = new WatchlistConfig
        {
            Vendors = new HashSet<string> { "apache" },
            Products = new HashSet<string> { "log4j" },
        };
        main.MergeFrom(other);

        Assert.Contains("microsoft", main.Vendors);
        Assert.Contains("apache", main.Vendors);
        Assert.Contains("windows", main.Products);
        Assert.Contains("log4j", main.Products);
    }
}
