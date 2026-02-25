using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Polly;
using Polly.Extensions.Http;

namespace VulnRadar.Downloaders;

/// <summary>HTTP download helpers for all VulnRadar data sources.</summary>
public static class DataDownloaders
{
    private const string GithubLatestReleaseApi =
        "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest";
    private const string CisaKevUrl =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private const string EpssCurrentCsvGzUrl =
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
    private const string PatchthisCsvUrl =
        "https://raw.githubusercontent.com/RogoLabs/patchthisapp/main/web/data.csv";
    private const string NvdFeedBaseUrl =
        "https://nvd.nist.gov/feeds/json/cve/2.0";

    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(120);

    private static readonly IAsyncPolicy<HttpResponseMessage> RetryPolicy =
        HttpPolicyExtensions
            .HandleTransientHttpError()
            .WaitAndRetryAsync(5, attempt => TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, attempt))));

    /// <summary>Create a configured HttpClient with auth and headers.</summary>
    public static HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.None,
        };

        var client = new HttpClient(handler)
        {
            Timeout = DefaultTimeout,
        };

        client.DefaultRequestHeaders.Add("User-Agent", "VulnRadar/0.2 (+https://github.com/)");
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN")
            ?? Environment.GetEnvironmentVariable("GH_TOKEN");
        if (!string.IsNullOrEmpty(token))
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        return client;
    }

    /// <summary>Fetch JSON from a URL with retry logic.</summary>
    public static async Task<JsonElement> GetJsonAsync(HttpClient client, string url)
    {
        using var response = await RetryWithPolicy(client, url);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(content).RootElement.Clone();
    }

    /// <summary>Download raw bytes from a URL with retry logic.</summary>
    public static async Task<byte[]> DownloadBytesAsync(HttpClient client, string url)
    {
        using var response = await RetryWithPolicy(client, url);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync();
    }

    private static async Task<HttpResponseMessage> RetryWithPolicy(HttpClient client, string url)
    {
        int attempt = 0;
        while (true)
        {
            try
            {
                var response = await client.GetAsync(url);
                if (response.IsSuccessStatusCode) return response;
                var code = (int)response.StatusCode;
                if (attempt >= 4 || (code < 500 && code != 429))
                    return response;
            }
            catch (Exception) when (attempt < 4)
            {
            }
            attempt++;
            var delay = Math.Min(30, Math.Pow(2, attempt));
            await Task.Delay(TimeSpan.FromSeconds(delay));
        }
    }

    // ─── CVE List V5 ──────────────────────────────────────────────────────────

    /// <summary>Resolve the download URL for the latest CVE List V5 bulk export.</summary>
    public static async Task<string> GetLatestCvelistZipUrlAsync(HttpClient client)
    {
        var data = await GetJsonAsync(client, GithubLatestReleaseApi);
        if (!data.TryGetProperty("assets", out var assets)) goto fail;

        foreach (var asset in assets.EnumerateArray())
        {
            var name = asset.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            if (Regex.IsMatch(name, @"_all_CVEs_at_midnight\.zip(\.zip)?$"))
            {
                var url = asset.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                if (!string.IsNullOrEmpty(url)) return url!;
            }
        }

        foreach (var asset in assets.EnumerateArray())
        {
            var name = asset.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            if (name.Contains("all_CVEs_at_midnight"))
            {
                var url = asset.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                if (!string.IsNullOrEmpty(url)) return url!;
            }
        }

        fail:
        throw new InvalidOperationException(
            "Could not find *_all_CVEs_at_midnight.zip asset in latest release");
    }

    /// <summary>Extract a CVE List ZIP to a temporary directory.</summary>
    public static string DownloadAndExtractZip(byte[] zipBytes)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), $"vulnradar_cvelist_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            using (var ms = new MemoryStream(zipBytes))
            using (var zf = new ZipArchive(ms, ZipArchiveMode.Read))
            {
                zf.ExtractToDirectory(tmpDir, overwriteFiles: true);
            }

            var nested = Path.Combine(tmpDir, "cves.zip");
            if (File.Exists(nested))
            {
                using var ms2 = new MemoryStream(File.ReadAllBytes(nested));
                using var zf2 = new ZipArchive(ms2, ZipArchiveMode.Read);
                zf2.ExtractToDirectory(tmpDir, overwriteFiles: true);
            }
        }
        catch
        {
            if (Directory.Exists(tmpDir)) Directory.Delete(tmpDir, recursive: true);
            throw;
        }

        return tmpDir;
    }

    // ─── CISA KEV ──────────────────────────────────────────────────────────────

    /// <summary>Download the CISA Known Exploited Vulnerabilities catalog.</summary>
    public static async Task<Dictionary<string, JsonElement>> DownloadCisaKevAsync(HttpClient client)
    {
        var data = await GetJsonAsync(client, CisaKevUrl);
        var out_ = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);

        if (!data.TryGetProperty("vulnerabilities", out var vulns)) return out_;
        if (vulns.ValueKind != JsonValueKind.Array) return out_;

        foreach (var v in vulns.EnumerateArray())
        {
            if (v.ValueKind != JsonValueKind.Object) continue;
            var cve = v.TryGetProperty("cveID", out var ci) ? (ci.GetString() ?? "").Trim().ToUpperInvariant() : "";
            if (cve.StartsWith("CVE-"))
                out_[cve] = v.Clone();
        }

        return out_;
    }

    // ─── EPSS ──────────────────────────────────────────────────────────────────

    /// <summary>Download FIRST.org EPSS daily probability scores.</summary>
    public static async Task<Dictionary<string, double>> DownloadEpssAsync(HttpClient client)
    {
        var raw = await DownloadBytesAsync(client, EpssCurrentCsvGzUrl);

        string text;
        using (var ms = new MemoryStream(raw))
        using (var gz = new GZipStream(ms, CompressionMode.Decompress))
        using (var sr = new StreamReader(gz, Encoding.UTF8))
        {
            text = await sr.ReadToEndAsync();
        }

        var out_ = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        string? headerLine = null;
        int cveIdx = -1, epssIdx = -1;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (string.IsNullOrEmpty(line)) continue;
            if (line.TrimStart().StartsWith("#")) continue;

            if (headerLine == null)
            {
                headerLine = line;
                var cols = headerLine.Split(',');
                for (var i = 0; i < cols.Length; i++)
                {
                    var c = cols[i].Trim().ToLowerInvariant();
                    if (c == "cve") cveIdx = i;
                    else if (c == "epss") epssIdx = i;
                }
                continue;
            }

            if (cveIdx < 0 || epssIdx < 0) continue;
            var parts = line.Split(',');
            if (parts.Length <= Math.Max(cveIdx, epssIdx)) continue;
            var cve = parts[cveIdx].Trim().ToUpperInvariant();
            if (!cve.StartsWith("CVE-")) continue;
            if (double.TryParse(parts[epssIdx].Trim(), System.Globalization.NumberStyles.Any,
                System.Globalization.CultureInfo.InvariantCulture, out var epss))
            {
                out_[cve] = epss;
            }
        }

        return out_;
    }

    // ─── PatchThis ──────────────────────────────────────────────────────────────

    /// <summary>Download PatchThis intelligence CSV as a set of CVE IDs.</summary>
    public static async Task<HashSet<string>> DownloadPatchthisAsync(HttpClient client)
    {
        var raw = await DownloadBytesAsync(client, PatchthisCsvUrl);
        var text = Encoding.UTF8.GetString(raw);
        var out_ = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string? headerLine = null;
        int cveIdx = -1;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            if (string.IsNullOrEmpty(line)) continue;

            if (headerLine == null)
            {
                headerLine = line;
                var cols = headerLine.Split(',');
                for (var i = 0; i < cols.Length; i++)
                {
                    var c = cols[i].Trim().ToLowerInvariant();
                    if (c is "cveid" or "cve_id" or "cve")
                    {
                        cveIdx = i;
                        break;
                    }
                }
                if (cveIdx < 0)
                    throw new InvalidOperationException(
                        "PatchThis CSV is missing a CVE identifier column (expected cveID)");
                continue;
            }

            var parts = line.Split(',');
            if (parts.Length <= cveIdx) continue;
            var cve = parts[cveIdx].Trim().ToUpperInvariant();
            if (cve.StartsWith("CVE-"))
                out_.Add(cve);
        }

        return out_;
    }

    // ─── NVD Feeds ──────────────────────────────────────────────────────────────

    /// <summary>Download NVD JSON 2.0 data feeds for the specified years.</summary>
    public static async Task<Dictionary<string, NvdItemData>> DownloadNvdFeedsAsync(
        HttpClient client,
        IEnumerable<int> years,
        string? cacheDir = null)
    {
        var nvdData = new Dictionary<string, NvdItemData>(StringComparer.OrdinalIgnoreCase);
        var yearsList = years.Distinct().OrderBy(y => y).ToList();

        if (cacheDir != null)
            Directory.CreateDirectory(cacheDir);

        foreach (var year in yearsList)
        {
            var url = $"{NvdFeedBaseUrl}/nvdcve-2.0-{year}.json.gz";
            var cacheFile = cacheDir != null ? Path.Combine(cacheDir, $"nvdcve-2.0-{year}.json.gz") : null;
            byte[]? raw = null;

            if (cacheFile != null && File.Exists(cacheFile))
            {
                var cacheAge = DateTime.UtcNow - File.GetLastWriteTimeUtc(cacheFile);
                if (cacheAge.TotalHours < 24)
                {
                    Console.WriteLine($"  Using cached NVD feed for {year} (age: {cacheAge.TotalHours:F1}h)");
                    raw = File.ReadAllBytes(cacheFile);
                }
            }

            if (raw == null)
            {
                Console.WriteLine($"  Downloading NVD feed for {year}...");
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    request.Headers.Add("Accept", "*/*");
                    using var response = await client.SendAsync(request);
                    response.EnsureSuccessStatusCode();
                    raw = await response.Content.ReadAsByteArrayAsync();
                    if (cacheFile != null)
                    {
                        File.WriteAllBytes(cacheFile, raw);
                        Console.WriteLine($"    Cached NVD feed for {year}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    Warning: Failed to download NVD feed for {year}: {ex.Message}");
                    continue;
                }
            }

            JsonElement feed;
            try
            {
                using var ms = new MemoryStream(raw);
                using var gz = new GZipStream(ms, CompressionMode.Decompress);
                using var sr = new StreamReader(gz, Encoding.UTF8);
                var feedText = await sr.ReadToEndAsync();
                feed = JsonDocument.Parse(feedText).RootElement.Clone();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Warning: Failed to parse NVD feed for {year}: {ex.Message}");
                continue;
            }

            var count = 0;
            if (!feed.TryGetProperty("vulnerabilities", out var vulns)) continue;
            if (vulns.ValueKind != JsonValueKind.Array) continue;

            foreach (var vuln in vulns.EnumerateArray())
            {
                if (!vuln.TryGetProperty("cve", out var cveData)) continue;
                var cveId = cveData.TryGetProperty("id", out var cid)
                    ? (cid.GetString() ?? "").Trim().ToUpperInvariant()
                    : "";
                if (!cveId.StartsWith("CVE-")) continue;

                var vulnStatus = cveData.TryGetProperty("vulnStatus", out var vs) ? vs.GetString() : null;
                if (vulnStatus == "Rejected") continue;

                var metrics = cveData.TryGetProperty("metrics", out var m) ? m : default;
                var cvss3Data = GetPrimaryCvss(metrics, "cvssMetricV31") ?? GetPrimaryCvss(metrics, "cvssMetricV30");
                var cvss2Data = GetPrimaryCvss(metrics, "cvssMetricV2");

                var cweIds = new List<string>();
                if (cveData.TryGetProperty("weaknesses", out var weaknesses))
                {
                    foreach (var weakness in weaknesses.EnumerateArray())
                    {
                        if (!weakness.TryGetProperty("description", out var descs)) continue;
                        foreach (var desc in descs.EnumerateArray())
                        {
                            var val = desc.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
                            if (val.StartsWith("CWE-") && val != "CWE-noinfo")
                                cweIds.Add(val);
                        }
                    }
                }

                var cpeCount = 0;
                if (cveData.TryGetProperty("configurations", out var configs))
                {
                    foreach (var config in configs.EnumerateArray())
                    {
                        if (!config.TryGetProperty("nodes", out var nodes)) continue;
                        foreach (var node in nodes.EnumerateArray())
                        {
                            if (node.TryGetProperty("cpeMatch", out var cpeMatch))
                                cpeCount += cpeMatch.GetArrayLength();
                        }
                    }
                }

                var refCount = cveData.TryGetProperty("references", out var refs)
                    ? refs.GetArrayLength()
                    : 0;

                nvdData[cveId] = new NvdItemData
                {
                    CvssV3Score = GetDoubleFromCvss(cvss3Data, "baseScore"),
                    CvssV3Severity = GetStringFromCvss(cvss3Data, "baseSeverity"),
                    CvssV3Vector = GetStringFromCvss(cvss3Data, "vectorString"),
                    CvssV2Score = GetDoubleFromCvss(cvss2Data, "baseScore"),
                    CvssV2Severity = GetStringFromCvss(cvss2Data, "baseSeverity"),
                    CvssV2Vector = GetStringFromCvss(cvss2Data, "vectorString"),
                    CweIds = cweIds.Distinct().Take(10).ToList().NullIfEmpty(),
                    CpeCount = cpeCount,
                    ReferenceCount = refCount,
                };
                count++;
            }

            Console.WriteLine($"    Loaded {count} CVEs from NVD {year} feed");
        }

        return nvdData;
    }

    private static JsonElement? GetPrimaryCvss(JsonElement metrics, string key)
    {
        if (metrics.ValueKind != JsonValueKind.Object) return null;
        if (!metrics.TryGetProperty(key, out var list)) return null;
        if (list.ValueKind != JsonValueKind.Array || list.GetArrayLength() == 0) return null;

        foreach (var m in list.EnumerateArray())
        {
            if (m.TryGetProperty("type", out var t) && t.GetString() == "Primary")
            {
                return m.TryGetProperty("cvssData", out var d) ? d : (JsonElement?)null;
            }
        }

        var first = list.EnumerateArray().FirstOrDefault();
        if (first.ValueKind == JsonValueKind.Object && first.TryGetProperty("cvssData", out var fd))
            return fd;
        return null;
    }

    private static double? GetDoubleFromCvss(JsonElement? cvss, string key)
    {
        if (cvss == null || cvss.Value.ValueKind != JsonValueKind.Object) return null;
        if (!cvss.Value.TryGetProperty(key, out var prop)) return null;
        if (prop.ValueKind == JsonValueKind.Number && prop.TryGetDouble(out var d)) return d;
        if (prop.ValueKind == JsonValueKind.String && double.TryParse(prop.GetString(),
            System.Globalization.NumberStyles.Any,
            System.Globalization.CultureInfo.InvariantCulture, out var sd)) return sd;
        return null;
    }

    private static string? GetStringFromCvss(JsonElement? cvss, string key)
    {
        if (cvss == null || cvss.Value.ValueKind != JsonValueKind.Object) return null;
        if (!cvss.Value.TryGetProperty(key, out var prop)) return null;
        return prop.GetString();
    }
}

/// <summary>NVD enrichment data for a single CVE.</summary>
public class NvdItemData
{
    public double? CvssV3Score { get; set; }
    public string? CvssV3Severity { get; set; }
    public string? CvssV3Vector { get; set; }
    public double? CvssV2Score { get; set; }
    public string? CvssV2Severity { get; set; }
    public string? CvssV2Vector { get; set; }
    public List<string>? CweIds { get; set; }
    public int CpeCount { get; set; }
    public int ReferenceCount { get; set; }
}

internal static class ListExtensions
{
    public static List<T>? NullIfEmpty<T>(this List<T> list) => list.Count == 0 ? null : list;
}
