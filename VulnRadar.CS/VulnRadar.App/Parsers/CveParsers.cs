using System.Text.Json;
using System.Text.RegularExpressions;

namespace VulnRadar.Parsers;

/// <summary>Represents an affected vendor/product entry in a CVE record.</summary>
public record AffectedEntry(string Vendor, string Product, JsonElement? Versions);

/// <summary>Parsed CVE record.</summary>
public record CveRecord(
    string CveId,
    string Description,
    double? CvssScore,
    string? CvssSeverity,
    string? CvssVector,
    List<AffectedEntry> Affected
);

/// <summary>Pure functions for extracting structured data from CVE List V5 JSON.</summary>
public static class CveParsers
{
    /// <summary>Normalize a string for case-insensitive comparison.</summary>
    public static string Norm(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        return Regex.Replace(s.Trim().ToLowerInvariant(), @"\s+", " ");
    }

    /// <summary>Select the best English description from CNA container.</summary>
    public static string PickBestDescription(JsonElement containersCna)
    {
        if (!containersCna.TryGetProperty("descriptions", out var descs)) return "";
        if (descs.ValueKind != JsonValueKind.Array) return "";

        // Try English first
        foreach (var d in descs.EnumerateArray())
        {
            if (d.ValueKind != JsonValueKind.Object) continue;
            var lang = d.TryGetProperty("lang", out var l) ? l.GetString() ?? "" : "";
            var value = d.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
            if (lang.StartsWith("en", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(value))
                return value;
        }

        // Fall back to any description
        foreach (var d in descs.EnumerateArray())
        {
            if (d.ValueKind != JsonValueKind.Object) continue;
            var value = d.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
            if (!string.IsNullOrEmpty(value)) return value;
        }

        return "";
    }

    /// <summary>Extract the best available CVSS score from CNA metrics.</summary>
    public static (double? Score, string? Severity, string? Vector) ExtractCvss(JsonElement containersCna)
    {
        if (!containersCna.TryGetProperty("metrics", out var metrics)) return (null, null, null);
        if (metrics.ValueKind != JsonValueKind.Array) return (null, null, null);

        foreach (var metric in metrics.EnumerateArray())
        {
            if (metric.ValueKind != JsonValueKind.Object) continue;

            foreach (var key in new[] { "cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0" })
            {
                if (!metric.TryGetProperty(key, out var cvss)) continue;
                if (cvss.ValueKind != JsonValueKind.Object) continue;

                double? score = null;
                if (cvss.TryGetProperty("baseScore", out var bs))
                {
                    if (bs.ValueKind == JsonValueKind.Number && bs.TryGetDouble(out var d))
                        score = d;
                    else if (bs.ValueKind == JsonValueKind.String && double.TryParse(bs.GetString(), out var sd))
                        score = sd;
                }

                if (score == null) continue;

                var severity = cvss.TryGetProperty("baseSeverity", out var sev) ? sev.GetString() : null;
                var vector = cvss.TryGetProperty("vectorString", out var vec) ? vec.GetString() : null;
                return (score, severity, vector);
            }
        }

        return (null, null, null);
    }

    /// <summary>Extract affected vendor/product pairs from CNA container.</summary>
    public static List<AffectedEntry> AffectedVendorProducts(JsonElement containersCna)
    {
        var results = new List<AffectedEntry>();
        if (!containersCna.TryGetProperty("affected", out var affected)) return results;
        if (affected.ValueKind != JsonValueKind.Array) return results;

        foreach (var a in affected.EnumerateArray())
        {
            if (a.ValueKind != JsonValueKind.Object) continue;
            var vendor = Norm(a.TryGetProperty("vendor", out var v) ? v.GetString() : null);
            var product = Norm(a.TryGetProperty("product", out var p) ? p.GetString() : null);
            JsonElement? versions = a.TryGetProperty("versions", out var ver) && ver.ValueKind == JsonValueKind.Array
                ? ver
                : null;
            results.Add(new AffectedEntry(vendor, product, versions));
        }

        return results;
    }

    /// <summary>Check whether a vendor/product pair matches the watchlist.</summary>
    public static bool MatchesWatchlist(
        string vendor,
        string product,
        HashSet<string> wlVendors,
        HashSet<string> wlProducts)
    {
        var v = Norm(vendor);
        var p = Norm(product);

        foreach (var wv in wlVendors)
        {
            if (string.IsNullOrEmpty(wv)) continue;
            if (v == wv || v.Contains(wv, StringComparison.Ordinal) || wv.Contains(v, StringComparison.Ordinal))
                return true;
        }

        foreach (var wp in wlProducts)
        {
            if (string.IsNullOrEmpty(wp)) continue;
            if (p == wp || p.Contains(wp, StringComparison.Ordinal) || wp.Contains(p, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>Parse a raw CVE V5 JSON element into a normalized record.</summary>
    public static CveRecord? ParseCveJsonData(JsonElement data)
    {
        var meta = data.TryGetProperty("cveMetadata", out var m) ? m : default;
        string cveId = "";
        if (meta.ValueKind == JsonValueKind.Object)
            cveId = meta.TryGetProperty("cveId", out var ci) ? ci.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(cveId))
            cveId = data.TryGetProperty("cveId", out var ci2) ? ci2.GetString() ?? "" : "";
        cveId = cveId.Trim().ToUpperInvariant();
        if (!cveId.StartsWith("CVE-")) return null;

        var containers = data.TryGetProperty("containers", out var c) ? c : default;
        JsonElement cna = default;
        if (containers.ValueKind == JsonValueKind.Object)
            containers.TryGetProperty("cna", out cna);

        var description = cna.ValueKind == JsonValueKind.Object ? PickBestDescription(cna) : "";
        var (cvssScore, cvssSeverity, cvssVector) = cna.ValueKind == JsonValueKind.Object
            ? ExtractCvss(cna)
            : (null, null, null);
        var affected = cna.ValueKind == JsonValueKind.Object
            ? AffectedVendorProducts(cna)
            : new List<AffectedEntry>();

        return new CveRecord(cveId, description, cvssScore, cvssSeverity, cvssVector, affected);
    }

    /// <summary>Extract year and sequence number from a CVE ID.</summary>
    public static (int Year, int Num)? CveYearAndNum(string? cveId)
    {
        if (string.IsNullOrEmpty(cveId)) return null;
        var m = Regex.Match(cveId.Trim(), @"^CVE-(\d{4})-(\d+)$", RegexOptions.IgnoreCase);
        if (!m.Success) return null;
        return (int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value));
    }

    /// <summary>Classify a radar item into a risk bucket.</summary>
    public static string RiskBucket(RadarItem item)
    {
        if (item.IsCritical) return "CRITICAL";
        if (item.ActiveThreat) return "KEV";
        if (item.ProbabilityScore.HasValue && item.ProbabilityScore.Value >= 0.7) return "High EPSS";
        if (item.CvssScore.HasValue && item.CvssScore.Value >= 9.0) return "Critical CVSS";
        return "Other";
    }

    /// <summary>Sort key for ordering radar items by risk (higher = higher priority).</summary>
    public static double RiskSortKey(RadarItem item)
    {
        var critical = item.IsCritical ? 1.0 : 0.0;
        var kev = item.ActiveThreat ? 1.0 : 0.0;
        var epss = item.ProbabilityScore ?? 0.0;
        var cvss = item.CvssScore ?? 0.0;
        return critical * 1000.0 + kev * 900.0 + epss * 10.0 + cvss;
    }

    /// <summary>Simple fuzzy matching score (higher = better match).</summary>
    public static double FuzzyScore(string query, string target)
    {
        query = query.ToLowerInvariant();
        target = target.ToLowerInvariant();
        if (query == target) return 1.0;
        if (target.Contains(query, StringComparison.Ordinal))
            return 0.8 + ((double)query.Length / target.Length) * 0.2;
        if (query.Contains(target, StringComparison.Ordinal)) return 0.6;
        var common = query.Count(c => target.Contains(c));
        return (double)common / Math.Max(query.Length, target.Length) * 0.5;
    }

    /// <summary>Format an EPSS score as a percentage string.</summary>
    public static string FormatEpss(double? epss) =>
        epss.HasValue ? $"{epss.Value * 100.0:F1}%" : "N/A";

    /// <summary>Format a CVSS score to 1 decimal place.</summary>
    public static string FormatCvss(double? cvss) =>
        cvss.HasValue ? cvss.Value.ToString("F1") : "N/A";
}
