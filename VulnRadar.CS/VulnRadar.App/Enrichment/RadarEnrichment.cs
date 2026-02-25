using System.Text.Json;
using VulnRadar.Downloaders;
using VulnRadar.Parsers;

namespace VulnRadar.Enrichment;

/// <summary>Enrichment and radar data assembly.</summary>
public static class RadarEnrichment
{
    /// <summary>Return the current UTC time as an ISO 8601 string.</summary>
    public static string NowUtcIso() =>
        DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK");

    /// <summary>Locate the cves/ directory inside an extracted CVE archive.</summary>
    public static string FindCvesRoot(string extractedDir)
    {
        var candidates = new List<string>();
        foreach (var dir in Directory.EnumerateDirectories(extractedDir, "cves",
            SearchOption.AllDirectories))
        {
            candidates.Add(dir);
        }
        if (candidates.Count == 0) return extractedDir;
        return candidates.OrderBy(p => p.Length).First();
    }

    /// <summary>Generate a list of years to scan.</summary>
    public static List<int> YearsToProcess(int minYear, int? maxYear)
    {
        var max = maxYear ?? DateTime.UtcNow.Year;
        if (max < minYear) return new List<int>();
        return Enumerable.Range(minYear, max - minYear + 1).ToList();
    }

    /// <summary>Yield paths to CVE JSON files for the given years.</summary>
    public static IEnumerable<string> IterCveJsonPaths(string cvesRoot, IEnumerable<int> years)
    {
        foreach (var year in years)
        {
            var yearDir = Path.Combine(cvesRoot, year.ToString());
            if (!Directory.Exists(yearDir)) continue;
            foreach (var file in Directory.EnumerateFiles(yearDir, "CVE-*.json",
                SearchOption.AllDirectories))
            {
                yield return file;
            }
        }
    }

    /// <summary>Guess the file path for a CVE ID using the standard directory layout.</summary>
    public static string? GuessCvePath(string cvesRoot, string cveId)
    {
        var parsed = CveParsers.CveYearAndNum(cveId);
        if (!parsed.HasValue) return null;
        var (year, num) = parsed.Value;
        var group = $"{num / 1000}xxx";
        var guess = Path.Combine(cvesRoot, year.ToString(), group, $"{cveId.ToUpperInvariant()}.json");
        if (File.Exists(guess)) return guess;

        var yearDir = Path.Combine(cvesRoot, year.ToString());
        if (!Directory.Exists(yearDir)) return null;
        return Directory.EnumerateFiles(yearDir, $"{cveId.ToUpperInvariant()}.json",
            SearchOption.AllDirectories).FirstOrDefault();
    }

    /// <summary>Load and parse a single CVE JSON file.</summary>
    public static CveRecord? ParseCveJson(string path)
    {
        try
        {
            var text = File.ReadAllText(path);
            var doc = JsonDocument.Parse(text);
            return CveParsers.ParseCveJsonData(doc.RootElement);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Assemble the final radar dataset.</summary>
    public static List<RadarItem> BuildRadarData(
        string extractedDir,
        HashSet<string> wlVendors,
        HashSet<string> wlProducts,
        Dictionary<string, JsonElement> kevByCve,
        Dictionary<string, double> epssByCve,
        HashSet<string> patchthisCves,
        Dictionary<string, NvdItemData> nvdByCve,
        int minYear,
        int? maxYear,
        bool includeKevOutsideWindow,
        double? severityThreshold = null,
        double? epssThreshold = null)
    {
        var cvesRoot = FindCvesRoot(extractedDir);
        var years = YearsToProcess(minYear, maxYear);
        var yearsSet = new HashSet<int>(years);

        var paths = new HashSet<string>(
            IterCveJsonPaths(cvesRoot, years),
            StringComparer.OrdinalIgnoreCase);

        if (includeKevOutsideWindow)
        {
            foreach (var cveId in kevByCve.Keys)
            {
                var yn = CveParsers.CveYearAndNum(cveId);
                if (!yn.HasValue) continue;
                if (yearsSet.Contains(yn.Value.Year)) continue;
                var p = GuessCvePath(cvesRoot, cveId);
                if (p != null) paths.Add(p);
            }
        }

        var items = new List<RadarItem>();

        foreach (var path in paths.OrderBy(p => p))
        {
            var parsed = ParseCveJson(path);
            if (parsed == null) continue;

            var cveId = parsed.CveId;
            var watchHit = false;
            var matchedTerms = new List<string>();

            foreach (var a in parsed.Affected)
            {
                if (CveParsers.MatchesWatchlist(a.Vendor, a.Product, wlVendors, wlProducts))
                {
                    watchHit = true;
                    if (!string.IsNullOrEmpty(a.Vendor))
                        matchedTerms.Add($"vendor:{a.Vendor}");
                    if (!string.IsNullOrEmpty(a.Product))
                        matchedTerms.Add($"product:{a.Product}");
                }
            }

            var kev = kevByCve.ContainsKey(cveId) ? kevByCve[cveId] : (JsonElement?)null;
            var activeThreat = kev.HasValue;
            var inPatchthis = patchthisCves.Contains(cveId);
            var inWatchlist = watchHit;

            // Criticality: patchthis + watchlist = critical
            var isCritical = inPatchthis && inWatchlist;

            double? cvssVal = parsed.CvssScore;
            double? epssVal = epssByCve.TryGetValue(cveId, out var ev) ? ev : null;

            if (!isCritical && inWatchlist && severityThreshold.HasValue && cvssVal.HasValue)
            {
                if (cvssVal.Value >= severityThreshold.Value)
                    isCritical = true;
            }

            if (!isCritical && inWatchlist && epssThreshold.HasValue && epssVal.HasValue)
            {
                if (epssVal.Value >= epssThreshold.Value)
                    isCritical = true;
            }

            string priorityLabel;
            if (isCritical)
            {
                if (inPatchthis && inWatchlist)
                    priorityLabel = "CRITICAL (Active Exploit in Stack)";
                else if (severityThreshold.HasValue && cvssVal.HasValue && cvssVal.Value >= severityThreshold.Value)
                    priorityLabel = $"CRITICAL (CVSS ≥ {severityThreshold.Value})";
                else if (epssThreshold.HasValue)
                    priorityLabel = $"CRITICAL (EPSS ≥ {epssThreshold.Value})";
                else
                    priorityLabel = "CRITICAL";
            }
            else
            {
                priorityLabel = "";
            }

            if (!inWatchlist && !activeThreat)
                continue;

            var item = new RadarItem
            {
                CveId = cveId,
                Description = parsed.Description,
                CvssScore = parsed.CvssScore,
                CvssSeverity = parsed.CvssSeverity,
                CvssVector = parsed.CvssVector,
                Affected = parsed.Affected.Select(a => new AffectedEntryJson { Vendor = a.Vendor, Product = a.Product }).ToList(),
                WatchlistHit = watchHit,
                InWatchlist = inWatchlist,
                InPatchthis = inPatchthis,
                IsCritical = isCritical,
                PriorityLabel = priorityLabel,
                MatchedTerms = watchHit
                    ? matchedTerms.Distinct().OrderBy(t => t).ToList()
                    : new List<string>(),
                ActiveThreat = activeThreat,
                ProbabilityScore = epssVal,
            };

            if (kev.HasValue)
            {
                var k = kev.Value;
                item.Kev = new KevEntry
                {
                    CveId = k.TryGetProperty("cveID", out var ki) ? ki.GetString() : null,
                    VendorProject = k.TryGetProperty("vendorProject", out var vp) ? vp.GetString() : null,
                    Product = k.TryGetProperty("product", out var kp) ? kp.GetString() : null,
                    VulnerabilityName = k.TryGetProperty("vulnerabilityName", out var vn) ? vn.GetString() : null,
                    DateAdded = k.TryGetProperty("dateAdded", out var da) ? da.GetString() : null,
                    ShortDescription = k.TryGetProperty("shortDescription", out var sd) ? sd.GetString() : null,
                    RequiredAction = k.TryGetProperty("requiredAction", out var ra) ? ra.GetString() : null,
                    DueDate = k.TryGetProperty("dueDate", out var dd) ? dd.GetString() : null,
                    KnownRansomwareCampaignUse = k.TryGetProperty("knownRansomwareCampaignUse", out var kr) ? kr.GetString() : null,
                };
            }

            if (nvdByCve.TryGetValue(cveId, out var nvd))
            {
                if (!item.CvssScore.HasValue && nvd.CvssV3Score.HasValue)
                {
                    item.CvssScore = nvd.CvssV3Score;
                    item.CvssSeverity = nvd.CvssV3Severity;
                    item.CvssVector = nvd.CvssV3Vector;
                }

                item.Nvd = new NvdEntry
                {
                    CvssV3Score = nvd.CvssV3Score,
                    CvssV3Severity = nvd.CvssV3Severity,
                    CvssV2Score = nvd.CvssV2Score,
                    CvssV2Severity = nvd.CvssV2Severity,
                    CweIds = nvd.CweIds,
                    CpeCount = nvd.CpeCount,
                    ReferenceCount = nvd.ReferenceCount,
                };
            }

            items.Add(item);
        }

        return items;
    }

    /// <summary>Write radar data to a JSON file atomically.</summary>
    public static void WriteRadarData(string path, List<RadarItem> items)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        var payload = new RadarDataPayload
        {
            GeneratedAt = NowUtcIso(),
            Count = items.Count,
            Items = items,
        };

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        });

        var tmp = path + ".tmp";
        File.WriteAllText(tmp, json + "\n");
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>Load radar items from a JSON file.</summary>
    public static List<RadarItem> LoadRadarData(string path)
    {
        if (!File.Exists(path)) return new List<RadarItem>();
        try
        {
            var text = File.ReadAllText(path);
            var payload = JsonSerializer.Deserialize<RadarDataPayload>(text,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return payload?.Items ?? new List<RadarItem>();
        }
        catch
        {
            return new List<RadarItem>();
        }
    }

    /// <summary>Extract all unique vendors and products from CVE data.</summary>
    public static (HashSet<string> Vendors, HashSet<string> Products) ExtractAllVendorsProducts(
        string extractedDir, IEnumerable<int> years)
    {
        var cvesRoot = FindCvesRoot(extractedDir);
        var vendors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var products = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "n/a", "unknown", "unspecified", "" };

        foreach (var path in IterCveJsonPaths(cvesRoot, years))
        {
            try
            {
                var text = File.ReadAllText(path);
                var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                if (!root.TryGetProperty("containers", out var containers)) continue;
                if (!containers.TryGetProperty("cna", out var cna)) continue;
                if (!cna.TryGetProperty("affected", out var affected)) continue;
                if (affected.ValueKind != JsonValueKind.Array) continue;

                foreach (var a in affected.EnumerateArray())
                {
                    if (a.ValueKind != JsonValueKind.Object) continue;
                    var v = CveParsers.Norm(a.TryGetProperty("vendor", out var vp) ? vp.GetString() : null);
                    var p = CveParsers.Norm(a.TryGetProperty("product", out var pp) ? pp.GetString() : null);
                    if (!skip.Contains(v) && !string.IsNullOrEmpty(v)) vendors.Add(v);
                    if (!skip.Contains(p) && !string.IsNullOrEmpty(p)) products.Add(p);
                }
            }
            catch
            {
                // skip bad files
            }
        }

        return (vendors, products);
    }
}
