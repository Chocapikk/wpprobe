<p align="center">
  <img src="./images/logo.jpg" width="400" alt="WPProbe" />
</p>

<p align="center"><b>"Because why scan blind when WordPress exposes itself?"</b></p>

---

<p align="center">
  <img src="./images/wpprobe.png" width="700" alt="WPProbe" />
</p>

[![Go CI](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml)
[![Latest Release](https://img.shields.io/github/v/release/Chocapikk/wpprobe)](https://github.com/Chocapikk/wpprobe/releases/latest)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-included-557C94?logo=kalilinux)](https://pkg.kali.org/pkg/wpprobe)

# WPProbe

A fast WordPress plugin scanner that detects installed plugins via REST API enumeration and maps them to known vulnerabilities. Over 5000 plugins detectable without brute-force, thousands more with it.

## Important: Wordfence API Change

Since March 9, 2026, Wordfence deprecated their v2 API. All WPProbe versions prior to v0.10.16 have broken `update-db` functionality. You need to update WPProbe.

By default, `wpprobe update-db` fetches a pre-built database from this repo (updated every 2h via CI), so no API key is needed. If you want to fetch directly from Wordfence yourself, you can optionally set up a free API key:

1. Create an account at [wordfence.com](https://www.wordfence.com)
2. Go to [Account > Integrations](https://www.wordfence.com/account/integrations) and generate an API key
3. Set it via environment variable or `--api-key` flag

## Quick Start

```sh
go install github.com/Chocapikk/wpprobe@latest
wpprobe update-db
wpprobe scan -u https://example.com
```

## Scanning Modes

| Mode | Method | Stealth | Coverage |
|------|--------|---------|----------|
| `stealthy` (default) | REST API endpoint matching | High | 5000+ plugins |
| `bruteforce` | Direct directory checks | Low | 10k+ plugins |
| `hybrid` | Stealthy first, then brute-force | Medium | Maximum |

```sh
wpprobe scan -u https://example.com --mode stealthy
wpprobe scan -u https://example.com --mode bruteforce
wpprobe scan -u https://example.com --mode hybrid
```

## Installation

```sh
# Kali Linux (included in kali-rolling)
sudo apt install wpprobe

# Go (requires 1.22+)
go install github.com/Chocapikk/wpprobe@latest

# Nix
nix-shell -p wpprobe

# Docker
docker run -it --rm wpprobe scan -u https://example.com

# From source
git clone https://github.com/Chocapikk/wpprobe && cd wpprobe && go build -o wpprobe
```

<details>
<summary>Docker with file mounting</summary>

```sh
# Mount current directory for input/output files
docker run -it --rm -v $(pwd):/data wpprobe scan -f /data/targets.txt -o /data/results.csv

# Persist vulnerability databases
docker run -it --rm \
  -v $(pwd):/data \
  -v wpprobe-config:/config \
  wpprobe scan -f /data/targets.txt -o /data/results.json

# Update databases
docker run -it --rm \
  -v wpprobe-config:/config \
  -e WORDFENCE_API_KEY=your_key \
  -e WPSCAN_API_TOKEN=your_token \
  wpprobe update-db
```

</details>

## Usage

### Scanning

```sh
# Single target
wpprobe scan -u https://example.com

# Multiple targets with threading
wpprobe scan -f targets.txt -t 20

# Custom options
wpprobe scan -u https://example.com \
  --header "User-Agent: CustomAgent" \
  --proxy http://proxy:8080 \
  --rate-limit 10 \
  --no-check-version

# Output formats
wpprobe scan -u https://example.com -o results.csv
wpprobe scan -u https://example.com -o results.json
```

### Vulnerability Database

```sh
# Update databases (Wordfence requires free API key, WPScan requires Enterprise API token)
wpprobe update-db --api-key your_wordfence_key
# Or use env var
export WORDFENCE_API_KEY=your_key_here
wpprobe update-db

# Search vulnerabilities
wpprobe search --cve CVE-2024-1234
wpprobe search --plugin woocommerce
wpprobe search --severity critical
wpprobe search --auth Unauth
wpprobe search --title "SQL Injection" --details

# Database statistics
wpprobe list
```

Set `WORDFENCE_API_KEY` for Wordfence database updates (free). Set `WPSCAN_API_TOKEN` for WPScan database updates (Enterprise plan only).

### Self-Update

```sh
wpprobe update
```

## How It Works

**Stealthy mode** queries exposed REST API routes (`?rest_route=/`) and matches discovered endpoints against a precompiled database of known plugin signatures. This generates minimal requests and avoids detection by WAFs.

**Brute-force mode** checks plugin directories directly via GET requests. A 403 response confirms the plugin exists (directory listing forbidden). A 200 response is validated by checking for `readme.txt` in the directory listing to avoid false positives from WordPress instances that return 200 for all paths.

**Hybrid mode** combines both: stealthy first for low-noise detection, then brute-force for remaining plugins.

Detected plugins are correlated with known CVEs from Wordfence and WPScan databases, with version range matching to identify vulnerable installations.

<details>
<summary>Output format examples</summary>

**CSV:**
```csv
URL,Plugin,Version,Severity,AuthType,CVEs,CVE Links,CVSS Score,CVSS Vector,Title
http://example.com,give,2.20.1,critical,Unauth,CVE-2025-22777,https://www.cve.org/CVERecord?id=CVE-2025-22777,9.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,GiveWP <= 3.19.3 - Unauthenticated PHP Object Injection
```

**JSON:**
```json
{
  "url": "http://example.com",
  "plugins": {
    "give": [
      {
        "version": "2.20.1",
        "severities": [
          {
            "critical": [
              {
                "auth_type": "Unauth",
                "vulnerabilities": [
                  {
                    "cve": "CVE-2025-22777",
                    "cvss_score": 9.8,
                    "title": "GiveWP <= 3.19.3 - Unauthenticated PHP Object Injection"
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}
```

</details>

## Limitations

- **Stealthy**: Some plugins don't expose REST API endpoints. Disabled or hidden plugins may not be detected.
- **Brute-force**: Generates many requests, may trigger WAFs or rate limits. Limited by wordlist coverage.
- **Hybrid**: Slower than pure stealthy due to the brute-force phase.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `WORDFENCE_API_KEY` | Wordfence API key for database updates (free, [get one here](https://www.wordfence.com/account/integrations)) |
| `WPSCAN_API_TOKEN` | WPScan Enterprise API token for database updates |
| `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` | Proxy configuration |
| `NO_PROXY` | Proxy bypass rules |

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## License

MIT License - see LICENSE file for details.

## Credits

Developed by [@Chocapikk](https://github.com/Chocapikk).

## Stats

<a href="https://star-history.com/#Chocapikk/wpprobe&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date" />
  </picture>
</a>
