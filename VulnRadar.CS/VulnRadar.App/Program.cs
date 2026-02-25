using System.CommandLine;
using System.Text.Json;
using VulnRadar.Config;
using VulnRadar.Downloaders;
using VulnRadar.Enrichment;
using VulnRadar.Notifications;
using VulnRadar.Parsers;
using VulnRadar.Report;
using VulnRadar.State;

// ─── Root command with subcommands ───────────────────────────────────────────

var rootCommand = new RootCommand("VulnRadar — Vulnerability Intelligence Radar (C# Edition)");

// ETL subcommand
var etlCommand = new Command("etl", "Run the ETL pipeline: download CVE data and build radar dataset");
AddEtlOptions(etlCommand);
etlCommand.SetHandler(RunEtl, new EtlOptionsBinder(etlCommand));
rootCommand.AddCommand(etlCommand);

// Notify subcommand
var notifyCommand = new Command("notify", "Send notifications for new/changed CVEs");
AddNotifyOptions(notifyCommand);
notifyCommand.SetHandler(RunNotify, new NotifyOptionsBinder(notifyCommand));
rootCommand.AddCommand(notifyCommand);

return await rootCommand.InvokeAsync(args);

// ─── ETL ──────────────────────────────────────────────────────────────────────

static void AddEtlOptions(Command cmd)
{
    cmd.AddOption(new Option<string?>("--watchlist", "Path to watchlist file (YAML or JSON)"));
    cmd.AddOption(new Option<string>("--out", () => "data/radar_data.json", "Output JSON path"));
    cmd.AddOption(new Option<string>("--report", () => "data/radar_report.md", "Output Markdown report path"));
    cmd.AddOption(new Option<int>("--min-year", () => DateTime.Now.Year - 4, "Minimum CVE year to scan"));
    cmd.AddOption(new Option<int?>("--max-year", "Maximum CVE year to scan"));
    cmd.AddOption(new Option<bool>("--include-kev-outside-window", "Include KEV entries outside the year range"));
    cmd.AddOption(new Option<bool>("--skip-nvd", "Skip NVD data feeds"));
    cmd.AddOption(new Option<string?>("--nvd-cache", "Directory to cache NVD feeds"));
    cmd.AddOption(new Option<string>("--state", () => "data/state.json", "Path to state file"));
    cmd.AddOption(new Option<string?>("--list-vendors", "List vendors matching a filter"));
    cmd.AddOption(new Option<string?>("--list-products", "List products matching a filter"));
    cmd.AddOption(new Option<bool>("--validate-watchlist", "Validate watchlist against CVE data"));
    cmd.AddOption(new Option<string?>("--search", "Fuzzy search vendors/products"));
}

static async Task<int> RunEtl(EtlOptions o)
{
    var watchlistPath = o.Watchlist ?? WatchlistLoader.FindWatchlist();
    Console.WriteLine($"Using watchlist: {watchlistPath}");

    WatchlistConfig wl;
    try
    {
        wl = WatchlistLoader.LoadMergedWatchlist(watchlistPath);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Failed to load watchlist: {ex.Message}");
        return 1;
    }

    var httpClient = DataDownloaders.CreateHttpClient();

    // Discovery commands
    if (o.ListVendors != null || o.ListProducts != null || o.ValidateWatchlist)
    {
        return await HandleDiscoveryAsync(httpClient, wl, o);
    }

    // Download CVE list
    Console.WriteLine("Downloading CVE List V5 bulk export...");
    string zipUrl;
    try
    {
        zipUrl = await DataDownloaders.GetLatestCvelistZipUrlAsync(httpClient);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Failed to get CVE list URL: {ex.Message}");
        return 1;
    }

    Console.WriteLine($"Downloading from: {zipUrl}");
    byte[] zipBytes;
    try
    {
        zipBytes = await DataDownloaders.DownloadBytesAsync(httpClient, zipUrl);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Failed to download CVE list: {ex.Message}");
        return 1;
    }

    Console.WriteLine("Extracting CVE archive...");
    string extractedDir;
    try
    {
        extractedDir = DataDownloaders.DownloadAndExtractZip(zipBytes);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Failed to extract ZIP: {ex.Message}");
        return 1;
    }

    try
    {
        // Download enrichment data in parallel
        Console.WriteLine("Downloading enrichment data...");
        var kevTask = DataDownloaders.DownloadCisaKevAsync(httpClient);
        var epssTask = DataDownloaders.DownloadEpssAsync(httpClient);
        var patchthisTask = DataDownloaders.DownloadPatchthisAsync(httpClient);

        await Task.WhenAll(kevTask, epssTask, patchthisTask);

        var kevByCve = kevTask.Result;
        var epssByCve = epssTask.Result;
        var patchthisCves = patchthisTask.Result;

        Console.WriteLine($"KEV: {kevByCve.Count} entries, EPSS: {epssByCve.Count} entries, PatchThis: {patchthisCves.Count} CVEs");

        // Download NVD feeds
        Dictionary<string, NvdItemData> nvdByCve = new();
        if (!o.SkipNvd)
        {
            Console.WriteLine("Downloading NVD feeds...");
            var years = RadarEnrichment.YearsToProcess(o.MinYear, o.MaxYear);
            try
            {
                nvdByCve = await DataDownloaders.DownloadNvdFeedsAsync(httpClient, years, o.NvdCache);
                Console.WriteLine($"NVD: {nvdByCve.Count} entries loaded");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: NVD download failed: {ex.Message}");
            }
        }

        // Build radar data
        Console.WriteLine("Building radar data...");
        var items = RadarEnrichment.BuildRadarData(
            extractedDir: extractedDir,
            wlVendors: wl.Vendors,
            wlProducts: wl.Products,
            kevByCve: kevByCve,
            epssByCve: epssByCve,
            patchthisCves: patchthisCves,
            nvdByCve: nvdByCve,
            minYear: o.MinYear,
            maxYear: o.MaxYear,
            includeKevOutsideWindow: o.IncludeKevOutsideWindow,
            severityThreshold: wl.Thresholds.SeverityThreshold,
            epssThreshold: wl.Thresholds.EpssThreshold);

        Console.WriteLine($"Found {items.Count} relevant CVEs");

        // Write output
        RadarEnrichment.WriteRadarData(o.Out, items);
        Console.WriteLine($"Radar data written to: {o.Out}");

        ReportWriter.WriteMarkdownReport(o.Report, items, o.State);
        Console.WriteLine($"Report written to: {o.Report}");

        return 0;
    }
    finally
    {
        if (Directory.Exists(extractedDir))
            Directory.Delete(extractedDir, recursive: true);
    }
}

static async Task<int> HandleDiscoveryAsync(
    HttpClient httpClient,
    WatchlistConfig wl,
    EtlOptions o)
{
    Console.WriteLine("Downloading CVE List V5 for discovery...");
    var zipUrl = await DataDownloaders.GetLatestCvelistZipUrlAsync(httpClient);
    var zipBytes = await DataDownloaders.DownloadBytesAsync(httpClient, zipUrl);
    var extractedDir = DataDownloaders.DownloadAndExtractZip(zipBytes);

    try
    {
        var currentYear = DateTime.Now.Year;
        var years = new[] { currentYear - 1, currentYear };

        Console.WriteLine("Scanning CVE data (last 2 years)...");
        var (allVendors, allProducts) = RadarEnrichment.ExtractAllVendorsProducts(extractedDir, years);
        Console.WriteLine($"  Found {allVendors.Count} unique vendors, {allProducts.Count} unique products");
        Console.WriteLine();

        if (o.ListVendors != null)
        {
            var filter = o.ListVendors.ToLowerInvariant();
            var matches = allVendors.Where(v => v.Contains(filter)).OrderBy(v => v).ToList();
            Console.WriteLine(string.IsNullOrEmpty(filter)
                ? $"All vendors ({matches.Count} total):"
                : $"Vendors containing '{filter}' ({matches.Count} matches):");
            Console.WriteLine(new string('-', 50));
            foreach (var v in matches.Take(200)) Console.WriteLine($"  {v}");
            if (matches.Count > 200) Console.WriteLine($"  ... and {matches.Count - 200} more");
            return 0;
        }

        if (o.ListProducts != null)
        {
            var filter = o.ListProducts.ToLowerInvariant();
            var matches = allProducts.Where(p => p.Contains(filter)).OrderBy(p => p).ToList();
            Console.WriteLine(string.IsNullOrEmpty(filter)
                ? $"All products ({matches.Count} total):"
                : $"Products containing '{filter}' ({matches.Count} matches):");
            Console.WriteLine(new string('-', 50));
            foreach (var p in matches.Take(200)) Console.WriteLine($"  {p}");
            if (matches.Count > 200) Console.WriteLine($"  ... and {matches.Count - 200} more");
            return 0;
        }

        if (o.ValidateWatchlist)
        {
            Console.WriteLine(new string('=', 60));
            Console.WriteLine($"\n📋 Vendors ({wl.Vendors.Count} in watchlist):");
            var matchedVendors = 0;
            foreach (var wv in wl.Vendors.OrderBy(v => v))
            {
                var matches = allVendors.Where(v => v.Contains(wv) || wv.Contains(v)).ToList();
                if (matches.Count > 0) { matchedVendors++; Console.WriteLine($"  ✅ {wv} → matches {matches.Count} vendor(s)"); }
                else Console.WriteLine($"  ⚠️  {wv} → no matches found");
            }

            Console.WriteLine($"\n📦 Products ({wl.Products.Count} in watchlist):");
            var matchedProducts = 0;
            foreach (var wp in wl.Products.OrderBy(p => p))
            {
                var matches = allProducts.Where(p => p.Contains(wp) || wp.Contains(p)).ToList();
                if (matches.Count > 0) { matchedProducts++; Console.WriteLine($"  ✅ {wp} → matches {matches.Count} product(s)"); }
                else Console.WriteLine($"  ⚠️  {wp} → no matches found");
            }

            Console.WriteLine($"\n{new string('=', 60)}");
            Console.WriteLine("Summary:");
            Console.WriteLine($"  Vendors:  {matchedVendors}/{wl.Vendors.Count} matched");
            Console.WriteLine($"  Products: {matchedProducts}/{wl.Products.Count} matched");
            return 0;
        }
    }
    finally
    {
        if (Directory.Exists(extractedDir))
            Directory.Delete(extractedDir, recursive: true);
    }

    return 0;
}

// ─── Notify ───────────────────────────────────────────────────────────────────

static void AddNotifyOptions(Command cmd)
{
    cmd.AddOption(new Option<string>("--inp", () => "data/radar_data.json", "Input radar data JSON"));
    cmd.AddOption(new Option<string>("--state-file", () => "data/state.json", "Path to state file"));
    cmd.AddOption(new Option<bool>("--no-state", "Disable state tracking"));
    cmd.AddOption(new Option<bool>("--force", "Force alerts even without changes"));
    cmd.AddOption(new Option<bool>("--dry-run", "Print actions without sending"));
    cmd.AddOption(new Option<bool>("--summary-every-run", "Send summary on every run"));
    cmd.AddOption(new Option<int>("--max-items", () => 25, "Maximum issues to create"));
    cmd.AddOption(new Option<string?>("--discord-webhook", "Discord webhook URL"));
    cmd.AddOption(new Option<string?>("--slack-webhook", "Slack webhook URL"));
    cmd.AddOption(new Option<string?>("--teams-webhook", "Teams webhook URL"));
    cmd.AddOption(new Option<int>("--discord-max", () => 10, "Max Discord alerts"));
    cmd.AddOption(new Option<int>("--slack-max", () => 10, "Max Slack alerts"));
    cmd.AddOption(new Option<int>("--teams-max", () => 10, "Max Teams alerts"));
    cmd.AddOption(new Option<bool>("--reset-state", "Delete state file and exit"));
    cmd.AddOption(new Option<int?>("--prune-state", "Prune CVEs not seen in N days"));
    cmd.AddOption(new Option<bool>("--demo", "Demo mode: inject a fake critical CVE"));
    cmd.AddOption(new Option<bool>("--weekly-summary", "Create a weekly summary issue"));
    cmd.AddOption(new Option<string?>("--watchlist", "Path to watchlist file"));
    cmd.AddOption(new Option<string?>("--project-url", "GitHub Projects v2 URL"));
}

static async Task<int> RunNotify(NotifyOptions o)
{
    var stateFile = o.StateFile;

    if (o.ResetState)
    {
        if (File.Exists(stateFile)) { File.Delete(stateFile); Console.WriteLine($"✅ Deleted state file: {stateFile}"); }
        else Console.WriteLine($"ℹ️  State file doesn't exist: {stateFile}");
        return 0;
    }

    if (o.PruneState.HasValue)
    {
        if (!File.Exists(stateFile)) { Console.WriteLine($"ℹ️  State file doesn't exist: {stateFile}"); return 0; }
        var ps = new StateManager(stateFile);
        var before = ps.GetStats()["total_tracked"];
        var pruned = ps.PruneOldEntries(o.PruneState.Value);
        ps.Save();
        Console.WriteLine($"✅ Pruned {pruned} CVEs not seen in {o.PruneState.Value} days");
        Console.WriteLine($"   Before: {before} tracked, After: {ps.GetStats()["total_tracked"]} tracked");
        return 0;
    }

    var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN")
        ?? Environment.GetEnvironmentVariable("GH_TOKEN");
    var repo = Environment.GetEnvironmentVariable("GITHUB_REPOSITORY");
    if (string.IsNullOrEmpty(repo)) { Console.Error.WriteLine("GITHUB_REPOSITORY is required"); return 1; }
    if (string.IsNullOrEmpty(token)) { Console.Error.WriteLine("GITHUB_TOKEN (or GH_TOKEN) is required"); return 1; }

    var items = RadarEnrichment.LoadRadarData(o.Inp);
    Console.WriteLine($"Loaded {items.Count} CVEs from {o.Inp}");

    // Load watchlist for baseline messages
    var wlPath = o.Watchlist ?? WatchlistLoader.FindWatchlist();
    WatchlistConfig wl = new();
    if (File.Exists(wlPath))
    {
        try { wl = WatchlistLoader.LoadMergedWatchlist(wlPath); }
        catch (Exception ex) { Console.WriteLine($"Warning: Could not load watchlist: {ex.Message}"); }
    }

    if (o.Demo)
    {
        var demo = GenerateDemoCve();
        items.Insert(0, demo);
        Console.WriteLine("\n🎭 DEMO MODE: Injected CVE-2099-DEMO (fake critical vulnerability)");
    }

    StateManager? state = null;
    if (!o.NoState)
    {
        state = new StateManager(stateFile);
        var stats = state.GetStats();
        Console.WriteLine($"State loaded: {stats["total_tracked"]} CVEs tracked, {stats["total_alerts_sent"]} alerts sent");
        var pruned = state.PruneOldEntries(180);
        if (pruned > 0) Console.WriteLine($"Pruned {pruned} CVEs not seen in 180 days");
    }

    // Weekly summary
    if (o.WeeklySummary)
    {
        Console.WriteLine("\n📊 Creating weekly summary issue...");
        var gh = new GitHubIssueProvider(token: token, repo: repo);
        gh.CreateWeeklySummary(items, state);
        return 0;
    }

    // Detect changes
    var changesByCve = new Dictionary<string, (RadarItem Item, List<Change> Changes)>(StringComparer.OrdinalIgnoreCase);
    foreach (var item in items)
    {
        var cveId = item.CveId.Trim().ToUpperInvariant();
        if (!cveId.StartsWith("CVE-")) continue;

        if (state != null && !o.Force)
        {
            var changes = state.DetectChanges(cveId, item);
            state.UpdateSnapshot(cveId, item);
            if (changes.Count > 0)
                changesByCve[cveId] = (item, changes);
        }
        else
        {
            if (item.IsCritical)
                changesByCve[cveId] = (item, new List<Change> { new Change { CveId = cveId, ChangeType = "NEW_CVE" } });
        }
    }

    // Filter to critical with changes
    var candidates = changesByCve.Values
        .Where(x => x.Item.IsCritical)
        .Select(x => x.Item)
        .OrderByDescending(i =>
        {
            var epss = i.ProbabilityScore ?? 0.0;
            var cvss = i.CvssScore ?? 0.0;
            return (i.IsCritical ? 1 : 0) * 1000.0 + (i.ActiveThreat ? 1 : 0) * 900.0 + epss * 10 + cvss;
        })
        .ToList();

    if (state != null && !o.Force)
    {
        if (changesByCve.Count > 0)
        {
            Console.WriteLine($"\n📊 Detected {changesByCve.Count} CVEs with changes:");
            foreach (var (_, (_, chs)) in changesByCve.Take(10))
                foreach (var ch in chs)
                    Console.WriteLine($"  {ch}");
            if (changesByCve.Count > 10) Console.WriteLine($"  ... and {changesByCve.Count - 10} more");
        }
        else
        {
            Console.WriteLine("\n✅ No new changes detected. Skipping notifications.");
        }
    }

    if (state != null && !o.Force && changesByCve.Count == 0)
    {
        if (!o.DryRun) { state.Save(); Console.WriteLine($"State saved to {stateFile}"); }
        return 0;
    }

    var isFirstRun = state != null && state.LastRun == null && !o.Force;

    // ── GitHub Issues ──────────────────────────────────────────────────────────
    var gh2 = new GitHubIssueProvider(
        token: token,
        repo: repo,
        maxAlerts: o.MaxItems,
        projectUrl: o.ProjectUrl ?? Environment.GetEnvironmentVariable("VULNRADAR_PROJECT_URL"));

    if (isFirstRun && candidates.Count > 5)
    {
        Console.WriteLine($"\n🚀 First run detected! Creating baseline summary instead of {candidates.Count} individual issues.");
        gh2.SendBaseline(items, candidates, repo,
            vendors: wl.Vendors.ToList(),
            products: wl.Products.ToList());
    }
    else
    {
        gh2.SendAll(candidates, changesByCve, o.DryRun);
    }

    // ── Webhook providers ──────────────────────────────────────────────────────
    var alertedChannels = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

    var webhookProviders = new List<NotificationProvider>();
    if (!string.IsNullOrEmpty(o.DiscordWebhook))
        webhookProviders.Add(new DiscordProvider(o.DiscordWebhook, o.DiscordMax));
    if (!string.IsNullOrEmpty(o.SlackWebhook))
        webhookProviders.Add(new SlackProvider(o.SlackWebhook, o.SlackMax));
    if (!string.IsNullOrEmpty(o.TeamsWebhook))
        webhookProviders.Add(new TeamsProvider(o.TeamsWebhook, o.TeamsMax));

    foreach (var provider in webhookProviders)
    {
        Console.WriteLine($"Sending {provider.Name} notifications...");
        try
        {
            if (isFirstRun && candidates.Count > 5)
            {
                provider.SendBaseline(items, candidates, repo,
                    vendors: wl.Vendors.ToList(), products: wl.Products.ToList());
                Console.WriteLine($"Sent {provider.Name} baseline summary (first run).");
            }
            else if (changesByCve.Count > 0 || o.Force || o.NoState)
            {
                if (o.SummaryEveryRun)
                {
                    provider.SendSummary(items, repo,
                        state != null ? changesByCve : null);
                    Console.WriteLine($"Sent {provider.Name} summary.");
                }

                int maxPerProvider = provider.Name switch
                {
                    "discord" => o.DiscordMax,
                    "slack" => o.SlackMax,
                    "teams" => o.TeamsMax,
                    _ => 10,
                };

                var sent = 0;
                foreach (var it in candidates.Take(maxPerProvider))
                {
                    var cveId = it.CveId.Trim().ToUpperInvariant();
                    var itemChanges = changesByCve.TryGetValue(cveId, out var cv) ? cv.Changes : new List<Change>();

                    if (o.DryRun)
                    {
                        Console.WriteLine($"DRY RUN: would send {provider.Name} alert for {cveId}");
                    }
                    else
                    {
                        var delay = provider.Name switch { "slack" => 1.0, _ => 0.5 };
                        await Task.Delay(TimeSpan.FromSeconds(delay));
                        provider.SendAlert(it, itemChanges);
                        Console.WriteLine($"Sent {provider.Name} alert for {cveId}");
                        if (!alertedChannels.ContainsKey(cveId)) alertedChannels[cveId] = new List<string>();
                        alertedChannels[cveId].Add(provider.Name);
                    }
                    sent++;
                }
                Console.WriteLine($"Sent {sent} {provider.Name} alerts.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{provider.Name} notification failed: {ex.Message}");
        }
    }

    // Save state
    if (state != null && !o.DryRun)
    {
        foreach (var (cveId, channels) in alertedChannels)
            state.MarkAlerted(cveId, channels);
        state.Save();
        var stats = state.GetStats();
        Console.WriteLine($"State saved to {stateFile} ({stats["total_tracked"]} CVEs tracked)");
    }

    return 0;
}

// ─── Demo CVE ─────────────────────────────────────────────────────────────────

static RadarItem GenerateDemoCve() => new RadarItem
{
    CveId = "CVE-2099-DEMO",
    Description = "🎭 DEMO: This is a fake critical vulnerability injected for demonstration purposes. It would represent a critical RCE vulnerability in a widely deployed component of your technology stack.",
    CvssScore = 9.8,
    CvssSeverity = "CRITICAL",
    CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    WatchlistHit = true,
    InWatchlist = true,
    InPatchthis = true,
    IsCritical = true,
    PriorityLabel = "CRITICAL (Active Exploit in Stack)",
    MatchedTerms = new List<string> { "vendor:demo-vendor", "product:demo-product" },
    ActiveThreat = true,
    ProbabilityScore = 0.95,
    Kev = new KevEntry
    {
        CveId = "CVE-2099-DEMO",
        VendorProject = "Demo Vendor",
        Product = "Demo Product",
        VulnerabilityName = "Demo RCE Vulnerability",
        DateAdded = DateTime.UtcNow.ToString("yyyy-MM-dd"),
        ShortDescription = "Demonstration CVE for VulnRadar testing.",
        RequiredAction = "Apply demo patch immediately.",
        DueDate = DateTime.UtcNow.AddDays(21).ToString("yyyy-MM-dd"),
        KnownRansomwareCampaignUse = "Known",
    },
};

// ─── Options models ───────────────────────────────────────────────────────────

class EtlOptions
{
    public string? Watchlist { get; set; }
    public string Out { get; set; } = "data/radar_data.json";
    public string Report { get; set; } = "data/radar_report.md";
    public int MinYear { get; set; } = DateTime.Now.Year - 4;
    public int? MaxYear { get; set; }
    public bool IncludeKevOutsideWindow { get; set; }
    public bool SkipNvd { get; set; }
    public string? NvdCache { get; set; }
    public string State { get; set; } = "data/state.json";
    public string? ListVendors { get; set; }
    public string? ListProducts { get; set; }
    public bool ValidateWatchlist { get; set; }
    public string? Search { get; set; }
}

class NotifyOptions
{
    public string Inp { get; set; } = "data/radar_data.json";
    public string StateFile { get; set; } = "data/state.json";
    public bool NoState { get; set; }
    public bool Force { get; set; }
    public bool DryRun { get; set; }
    public bool SummaryEveryRun { get; set; }
    public int MaxItems { get; set; } = 25;
    public string? DiscordWebhook { get; set; }
    public string? SlackWebhook { get; set; }
    public string? TeamsWebhook { get; set; }
    public int DiscordMax { get; set; } = 10;
    public int SlackMax { get; set; } = 10;
    public int TeamsMax { get; set; } = 10;
    public bool ResetState { get; set; }
    public int? PruneState { get; set; }
    public bool Demo { get; set; }
    public bool WeeklySummary { get; set; }
    public string? Watchlist { get; set; }
    public string? ProjectUrl { get; set; }
}

class EtlOptionsBinder : System.CommandLine.Binding.BinderBase<EtlOptions>
{
    private readonly Command _cmd;
    public EtlOptionsBinder(Command cmd) => _cmd = cmd;

    protected override EtlOptions GetBoundValue(System.CommandLine.Binding.BindingContext ctx) => new EtlOptions
    {
        Watchlist = GetValue<string?>(ctx, "--watchlist"),
        Out = GetValue<string>(ctx, "--out") ?? "data/radar_data.json",
        Report = GetValue<string>(ctx, "--report") ?? "data/radar_report.md",
        MinYear = GetValue<int>(ctx, "--min-year"),
        MaxYear = GetValue<int?>(ctx, "--max-year"),
        IncludeKevOutsideWindow = GetValue<bool>(ctx, "--include-kev-outside-window"),
        SkipNvd = GetValue<bool>(ctx, "--skip-nvd"),
        NvdCache = GetValue<string?>(ctx, "--nvd-cache"),
        State = GetValue<string>(ctx, "--state") ?? "data/state.json",
        ListVendors = GetValue<string?>(ctx, "--list-vendors"),
        ListProducts = GetValue<string?>(ctx, "--list-products"),
        ValidateWatchlist = GetValue<bool>(ctx, "--validate-watchlist"),
        Search = GetValue<string?>(ctx, "--search"),
    };

    private T GetValue<T>(System.CommandLine.Binding.BindingContext ctx, string name)
    {
        var opt = _cmd.Options.FirstOrDefault(o => o.Name == name[2..]);
        if (opt == null) return default!;
        return (T)ctx.ParseResult.GetValueForOption(opt)!;
    }
}

class NotifyOptionsBinder : System.CommandLine.Binding.BinderBase<NotifyOptions>
{
    private readonly Command _cmd;
    public NotifyOptionsBinder(Command cmd) => _cmd = cmd;

    protected override NotifyOptions GetBoundValue(System.CommandLine.Binding.BindingContext ctx) => new NotifyOptions
    {
        Inp = GetValue<string>(ctx, "--inp") ?? "data/radar_data.json",
        StateFile = GetValue<string>(ctx, "--state-file") ?? "data/state.json",
        NoState = GetValue<bool>(ctx, "--no-state"),
        Force = GetValue<bool>(ctx, "--force"),
        DryRun = GetValue<bool>(ctx, "--dry-run"),
        SummaryEveryRun = GetValue<bool>(ctx, "--summary-every-run"),
        MaxItems = GetValue<int>(ctx, "--max-items"),
        DiscordWebhook = GetValue<string?>(ctx, "--discord-webhook"),
        SlackWebhook = GetValue<string?>(ctx, "--slack-webhook"),
        TeamsWebhook = GetValue<string?>(ctx, "--teams-webhook"),
        DiscordMax = GetValue<int>(ctx, "--discord-max"),
        SlackMax = GetValue<int>(ctx, "--slack-max"),
        TeamsMax = GetValue<int>(ctx, "--teams-max"),
        ResetState = GetValue<bool>(ctx, "--reset-state"),
        PruneState = GetValue<int?>(ctx, "--prune-state"),
        Demo = GetValue<bool>(ctx, "--demo"),
        WeeklySummary = GetValue<bool>(ctx, "--weekly-summary"),
        Watchlist = GetValue<string?>(ctx, "--watchlist"),
        ProjectUrl = GetValue<string?>(ctx, "--project-url"),
    };

    private T GetValue<T>(System.CommandLine.Binding.BindingContext ctx, string name)
    {
        var opt = _cmd.Options.FirstOrDefault(o => o.Name == name[2..]);
        if (opt == null) return default!;
        return (T)ctx.ParseResult.GetValueForOption(opt)!;
    }
}
