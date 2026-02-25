using System.Text.RegularExpressions;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace VulnRadar.Config;

/// <summary>Optional severity thresholds for filtering and criticality.</summary>
public class ThresholdsConfig
{
    public double MinCvss { get; set; } = 0.0;
    public double MinEpss { get; set; } = 0.0;
    public double? SeverityThreshold { get; set; } = null;
    public double? EpssThreshold { get; set; } = null;
}

/// <summary>Optional behaviour flags.</summary>
public class OptionsConfig
{
    public bool AlwaysIncludeKev { get; set; } = true;
    public bool AlwaysIncludePatchthis { get; set; } = true;
    public string MatchMode { get; set; } = "substring";
}

/// <summary>A single notification destination with optional severity filter.</summary>
public class NotificationRoute
{
    public string Url { get; set; } = "";
    public string Filter { get; set; } = "all";
    public int MaxAlerts { get; set; } = 10;
}

/// <summary>Optional per-provider notification routing.</summary>
public class NotificationsConfig
{
    public List<NotificationRoute> Discord { get; set; } = new();
    public List<NotificationRoute> Slack { get; set; } = new();
    public List<NotificationRoute> Teams { get; set; } = new();
}

/// <summary>Validated watchlist configuration.</summary>
public class WatchlistConfig
{
    public HashSet<string> Vendors { get; set; } = new();
    public HashSet<string> Products { get; set; } = new();
    public HashSet<string> ExcludeVendors { get; set; } = new();
    public HashSet<string> ExcludeProducts { get; set; } = new();
    public ThresholdsConfig Thresholds { get; set; } = new();
    public OptionsConfig Options { get; set; } = new();
    public NotificationsConfig Notifications { get; set; } = new();

    /// <summary>Normalize and merge another config into this one.</summary>
    public void MergeFrom(WatchlistConfig other)
    {
        foreach (var v in other.Vendors) Vendors.Add(v);
        foreach (var p in other.Products) Products.Add(p);
        foreach (var v in other.ExcludeVendors) ExcludeVendors.Add(v);
        foreach (var p in other.ExcludeProducts) ExcludeProducts.Add(p);
    }

    /// <summary>Normalize a string set: lowercase, strip, collapse whitespace.</summary>
    public static HashSet<string> NormalizeSet(IEnumerable<string>? items)
    {
        if (items == null) return new HashSet<string>();
        var result = new HashSet<string>();
        foreach (var item in items)
        {
            var normalized = Regex.Replace(item.Trim().ToLowerInvariant(), @"\s+", " ");
            if (!string.IsNullOrEmpty(normalized))
                result.Add(normalized);
        }
        return result;
    }
}

/// <summary>Raw YAML deserialization model (snake_case YAML keys).</summary>
internal class RawWatchlist
{
    public List<string>? vendors { get; set; }
    public List<string>? products { get; set; }
    public List<string>? exclude_vendors { get; set; }
    public List<string>? exclude_products { get; set; }
    public RawThresholds? thresholds { get; set; }
    public RawOptions? options { get; set; }
    public RawNotifications? notifications { get; set; }
}

internal class RawThresholds
{
    public double? min_cvss { get; set; }
    public double? min_epss { get; set; }
    public double? severity_threshold { get; set; }
    public double? epss_threshold { get; set; }
}

internal class RawOptions
{
    public bool? always_include_kev { get; set; }
    public bool? always_include_patchthis { get; set; }
    public string? match_mode { get; set; }
}

internal class RawNotifications
{
    public List<RawNotificationRoute>? discord { get; set; }
    public List<RawNotificationRoute>? slack { get; set; }
    public List<RawNotificationRoute>? teams { get; set; }
}

internal class RawNotificationRoute
{
    public string? url { get; set; }
    public string? filter { get; set; }
    public int? max_alerts { get; set; }
}

/// <summary>Loads and merges watchlist configuration from YAML/JSON files.</summary>
public static class WatchlistLoader
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .IgnoreUnmatchedProperties()
        .Build();

    /// <summary>Load a watchlist from a YAML or JSON file.</summary>
    public static WatchlistConfig LoadWatchlist(string path)
    {
        var content = File.ReadAllText(path);
        RawWatchlist raw;

        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext == ".json")
        {
            Console.WriteLine("Note: JSON watchlists are deprecated. Consider migrating to watchlist.yaml");
            raw = System.Text.Json.JsonSerializer.Deserialize<RawWatchlist>(content,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new RawWatchlist();
        }
        else
        {
            raw = YamlDeserializer.Deserialize<RawWatchlist>(content) ?? new RawWatchlist();
        }

        return MapRaw(raw);
    }

    private static WatchlistConfig MapRaw(RawWatchlist raw)
    {
        var cfg = new WatchlistConfig
        {
            Vendors = WatchlistConfig.NormalizeSet(raw.vendors),
            Products = WatchlistConfig.NormalizeSet(raw.products),
            ExcludeVendors = WatchlistConfig.NormalizeSet(raw.exclude_vendors),
            ExcludeProducts = WatchlistConfig.NormalizeSet(raw.exclude_products),
        };

        if (raw.thresholds != null)
        {
            cfg.Thresholds = new ThresholdsConfig
            {
                MinCvss = raw.thresholds.min_cvss ?? 0.0,
                MinEpss = raw.thresholds.min_epss ?? 0.0,
                SeverityThreshold = raw.thresholds.severity_threshold,
                EpssThreshold = raw.thresholds.epss_threshold,
            };
        }

        if (raw.options != null)
        {
            cfg.Options = new OptionsConfig
            {
                AlwaysIncludeKev = raw.options.always_include_kev ?? true,
                AlwaysIncludePatchthis = raw.options.always_include_patchthis ?? true,
                MatchMode = raw.options.match_mode ?? "substring",
            };
        }

        if (raw.notifications != null)
        {
            cfg.Notifications = new NotificationsConfig
            {
                Discord = MapRoutes(raw.notifications.discord),
                Slack = MapRoutes(raw.notifications.slack),
                Teams = MapRoutes(raw.notifications.teams),
            };
        }

        return cfg;
    }

    private static List<NotificationRoute> MapRoutes(List<RawNotificationRoute>? routes)
    {
        if (routes == null) return new List<NotificationRoute>();
        return routes.Select(r => new NotificationRoute
        {
            Url = r.url ?? "",
            Filter = r.filter ?? "all",
            MaxAlerts = r.max_alerts ?? 10,
        }).ToList();
    }

    /// <summary>Load and merge watchlists from a main file and optional directory.</summary>
    public static WatchlistConfig LoadMergedWatchlist(string mainPath, string? watchlistDir = null)
    {
        var main = LoadWatchlist(mainPath);

        var dir = watchlistDir ?? "watchlist.d";
        if (Directory.Exists(dir))
        {
            var yamlFiles = Directory.GetFiles(dir, "*.yaml")
                .Concat(Directory.GetFiles(dir, "*.yml"))
                .OrderBy(f => f)
                .ToList();

            if (yamlFiles.Count > 0)
            {
                Console.WriteLine($"Merging {yamlFiles.Count} additional watchlist(s) from {dir}/");
                foreach (var file in yamlFiles)
                {
                    try
                    {
                        var extra = LoadWatchlist(file);
                        main.MergeFrom(extra);
                        Console.WriteLine($"  + {Path.GetFileName(file)}: {extra.Vendors.Count} vendors, {extra.Products.Count} products");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  ⚠️ Failed to load {Path.GetFileName(file)}: {ex.Message}");
                    }
                }
            }
        }

        return main;
    }

    /// <summary>Find the watchlist file, preferring YAML over JSON.</summary>
    public static string FindWatchlist()
    {
        foreach (var name in new[] { "watchlist.yaml", "watchlist.yml", "watchlist.json" })
        {
            if (File.Exists(name)) return name;
        }
        return "watchlist.yaml";
    }
}
