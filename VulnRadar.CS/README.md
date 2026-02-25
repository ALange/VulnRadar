# VulnRadar C# Edition

A modern C# (.NET 8) port of the [VulnRadar](https://github.com/ALange/VulnRadar) vulnerability intelligence platform.

## Overview

VulnRadar monitors CVE (Common Vulnerabilities and Exposures) data from multiple sources and alerts security teams when vulnerabilities affect their technology stack.

## Data Sources

- **CVE List V5** — Official CVE database from CVEProject
- **CISA KEV** — CISA Known Exploited Vulnerabilities catalog
- **EPSS** — Exploit Prediction Scoring System (FIRST.org)
- **PatchThis** — Exploit intelligence from RogoLabs
- **NVD** — National Vulnerability Database enrichment

## Architecture

```
VulnRadar.CS/
├── VulnRadar.App/
│   ├── Config/          # Watchlist loading (YAML/JSON)
│   ├── Parsers/         # CVE JSON parsing, CVSS extraction, watchlist matching
│   ├── Downloaders/     # HTTP fetching with retry (CVE list, KEV, EPSS, PatchThis, NVD)
│   ├── Enrichment/      # Build radar data, file traversal, ZIP extraction
│   ├── State/           # Persistent state tracking to prevent duplicate alerts
│   ├── Report/          # Markdown report generation
│   ├── Notifications/   # Discord, Slack, Teams, GitHub Issues providers
│   └── Program.cs       # CLI entry point
└── VulnRadar.Tests/     # xUnit test suite
```

## Prerequisites

- .NET 8.0 SDK or later

## Building

```bash
dotnet build
```

## Running

### ETL Pipeline

Download CVE data and build radar dataset:

```bash
dotnet run --project VulnRadar.App -- etl \
  --watchlist watchlist.yaml \
  --out data/radar_data.json \
  --report data/radar_report.md
```

### Skip NVD (faster, for testing)

```bash
dotnet run --project VulnRadar.App -- etl --skip-nvd
```

### Discover vendors/products

```bash
dotnet run --project VulnRadar.App -- etl --list-vendors "microsoft"
dotnet run --project VulnRadar.App -- etl --list-products "log4j"
```

### Validate watchlist

```bash
dotnet run --project VulnRadar.App -- etl --validate-watchlist
```

### Notify Pipeline

Send notifications for new/changed CVEs:

```bash
GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo \
dotnet run --project VulnRadar.App -- notify \
  --inp data/radar_data.json \
  --discord-webhook https://discord.com/api/webhooks/...
```

### Dry-run mode

```bash
dotnet run --project VulnRadar.App -- notify --dry-run --no-state
```

## Configuration

The watchlist file (`watchlist.yaml`) specifies which vendors and products to monitor:

```yaml
vendors:
  - microsoft
  - apache
products:
  - log4j
  - spring-framework
thresholds:
  min_cvss: 0.0
  severity_threshold: 9.0   # Flag as critical if CVSS >= 9.0 and on watchlist
  epss_threshold: 0.5       # Flag as critical if EPSS >= 50% and on watchlist
options:
  always_include_kev: true
  always_include_patchthis: true
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` or `GH_TOKEN` | GitHub personal access token for API access |
| `GITHUB_REPOSITORY` | Repository slug (e.g., `owner/repo`) |
| `VULNRADAR_PROJECT_URL` | GitHub Projects v2 URL for issue tracking |

## Running Tests

```bash
dotnet test
```

## Notifications

Supported notification channels:

- **GitHub Issues** — Creates issues for critical CVEs
- **Discord** — Rich embeds via webhook
- **Slack** — Block Kit messages via webhook
- **Microsoft Teams** — Adaptive Cards via webhook

## State Management

VulnRadar tracks seen CVEs to prevent duplicate alerts:

```bash
# Reset state
dotnet run --project VulnRadar.App -- notify --reset-state

# Prune CVEs not seen in 90 days
dotnet run --project VulnRadar.App -- notify --prune-state 90
```

## Criticality Logic

A CVE is marked **CRITICAL** when:
1. It appears in **PatchThis** (exploit PoC) AND matches your **watchlist**
2. Its **CVSS score** is at/above `severity_threshold` AND matches your watchlist
3. Its **EPSS probability** is at/above `epss_threshold` AND matches your watchlist
