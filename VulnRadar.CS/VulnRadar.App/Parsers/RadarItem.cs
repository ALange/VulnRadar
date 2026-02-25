using System.Text.Json;
using System.Text.Json.Serialization;

namespace VulnRadar.Parsers;

/// <summary>Enriched CVE radar item combining CVE data with KEV, EPSS, PatchThis, and NVD.</summary>
public class RadarItem
{
    [JsonPropertyName("cve_id")]
    public string CveId { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("cvss_score")]
    public double? CvssScore { get; set; }

    [JsonPropertyName("cvss_severity")]
    public string? CvssSeverity { get; set; }

    [JsonPropertyName("cvss_vector")]
    public string? CvssVector { get; set; }

    [JsonPropertyName("watchlist_hit")]
    public bool WatchlistHit { get; set; }

    [JsonPropertyName("in_watchlist")]
    public bool InWatchlist { get; set; }

    [JsonPropertyName("in_patchthis")]
    public bool InPatchthis { get; set; }

    [JsonPropertyName("is_critical")]
    public bool IsCritical { get; set; }

    [JsonPropertyName("priority_label")]
    public string PriorityLabel { get; set; } = "";

    [JsonPropertyName("matched_terms")]
    public List<string> MatchedTerms { get; set; } = new();

    [JsonPropertyName("active_threat")]
    public bool ActiveThreat { get; set; }

    [JsonPropertyName("probability_score")]
    public double? ProbabilityScore { get; set; }

    [JsonPropertyName("kev")]
    public KevEntry? Kev { get; set; }

    [JsonPropertyName("nvd")]
    public NvdEntry? Nvd { get; set; }

    [JsonPropertyName("affected")]
    public List<AffectedEntryJson> Affected { get; set; } = new();

    [JsonPropertyName("bucket")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Bucket { get; set; }
}

public class AffectedEntryJson
{
    [JsonPropertyName("vendor")]
    public string Vendor { get; set; } = "";

    [JsonPropertyName("product")]
    public string Product { get; set; } = "";
}

public class KevEntry
{
    [JsonPropertyName("cveID")]
    public string? CveId { get; set; }

    [JsonPropertyName("vendorProject")]
    public string? VendorProject { get; set; }

    [JsonPropertyName("product")]
    public string? Product { get; set; }

    [JsonPropertyName("vulnerabilityName")]
    public string? VulnerabilityName { get; set; }

    [JsonPropertyName("dateAdded")]
    public string? DateAdded { get; set; }

    [JsonPropertyName("shortDescription")]
    public string? ShortDescription { get; set; }

    [JsonPropertyName("requiredAction")]
    public string? RequiredAction { get; set; }

    [JsonPropertyName("dueDate")]
    public string? DueDate { get; set; }

    [JsonPropertyName("knownRansomwareCampaignUse")]
    public string? KnownRansomwareCampaignUse { get; set; }
}

public class NvdEntry
{
    [JsonPropertyName("cvss_v3_score")]
    public double? CvssV3Score { get; set; }

    [JsonPropertyName("cvss_v3_severity")]
    public string? CvssV3Severity { get; set; }

    [JsonPropertyName("cvss_v2_score")]
    public double? CvssV2Score { get; set; }

    [JsonPropertyName("cvss_v2_severity")]
    public string? CvssV2Severity { get; set; }

    [JsonPropertyName("cwe_ids")]
    public List<string>? CweIds { get; set; }

    [JsonPropertyName("cpe_count")]
    public int? CpeCount { get; set; }

    [JsonPropertyName("reference_count")]
    public int? ReferenceCount { get; set; }
}

/// <summary>The output payload written to radar_data.json.</summary>
public class RadarDataPayload
{
    [JsonPropertyName("generated_at")]
    public string GeneratedAt { get; set; } = "";

    [JsonPropertyName("count")]
    public int Count { get; set; }

    [JsonPropertyName("items")]
    public List<RadarItem> Items { get; set; } = new();
}
