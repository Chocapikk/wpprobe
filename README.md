![WPProbe](./images/logo.jpg)

**"Because why scan blind when WordPress exposes itself?"**

---

![WPProbe](./images/wpprobe.png)

[![Go CI](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/Chocapikk/wpprobe/actions/workflows/go.yml)
[![Latest Release](https://img.shields.io/github/v/release/Chocapikk/wpprobe)](https://github.com/Chocapikk/wpprobe/releases/latest)

# WPProbe

A fast and efficient WordPress plugin scanner that leverages REST API enumeration to detect installed plugins without brute-force. WPProbe identifies plugins by querying exposed REST API endpoints and correlates them with known vulnerabilities from Wordfence and WPScan databases.

## Overview

WPProbe uses WordPress REST API endpoints (`?rest_route`) to detect installed plugins by matching discovered endpoints with known plugin signatures. This approach is faster and more stealthy than traditional brute-force methods, reducing detection risks and speeding up the scan process.

Over 3000 plugins can be identified using the stealthy REST API method, with thousands more detectable through brute-force capabilities.

## Features

- **Multiple scanning modes**: Stealthy (REST API), brute-force, and hybrid
- **Vulnerability mapping**: Automatically associates detected plugins with known CVEs from Wordfence and WPScan databases
- **High-speed scanning**: Multithreaded scanning with progress tracking
- **Multiple output formats**: CSV and JSON output formats
- **Vulnerability search**: Search and filter vulnerabilities by CVE, plugin, severity, and more
- **Database management**: Update vulnerability databases from Wordfence and WPScan (Enterprise)

## Installation

### Quick Install

```bash
go install github.com/Chocapikk/wpprobe@latest
```

Requires Go 1.22+. Ensure `$(go env GOPATH)/bin` is in your `$PATH`.

### Manual Build

```bash
git clone https://github.com/Chocapikk/wpprobe
cd wpprobe
go mod tidy
go build -o wpprobe
```

Move the `wpprobe` binary to a directory in your `$PATH`.

### Docker

Build the image:
```bash
docker build -t wpprobe .
```

Basic usage:
```bash
docker run -it --rm wpprobe scan -u https://example.com
```

With file mounting (targets, outputs, plugin lists):
```bash
# Mount current directory for input/output files
docker run -it --rm -v $(pwd):/data wpprobe scan -f /data/targets.txt -o /data/results.csv

# Mount separate volumes for data and config (vulnerability databases)
docker run -it --rm \
  -v $(pwd):/data \
  -v wpprobe-config:/config \
  wpprobe scan -f /data/targets.txt -o /data/results.json

# Update vulnerability databases (persisted in config volume)
docker run -it --rm \
  -v wpprobe-config:/config \
  -e WPSCAN_API_TOKEN=your_token \
  wpprobe update-db
```

### Nix

```bash
nix-shell -p wpprobe
```

## Usage

### Update Vulnerability Databases

Update both Wordfence and WPScan (Enterprise) vulnerability databases:

```bash
wpprobe update-db
```

**Note**: WPScan database update requires an Enterprise plan API token. Set `WPSCAN_API_TOKEN` environment variable. Wordfence database is free and unlimited.

**Warning**: WPScan integration has not been fully tested yet. Use with caution.

### Scan Single Target

Scan a WordPress site using the default stealthy mode:

```bash
wpprobe scan -u https://example.com
```

### Scan Multiple Targets

Scan multiple sites from a file:

```bash
wpprobe scan -f targets.txt -t 20
```

### Scanning Modes

**Stealthy mode (default)**: Uses REST API endpoints for detection
```bash
wpprobe scan -u https://example.com --mode stealthy
```

**Brute-force mode**: Direct plugin directory checks
```bash
wpprobe scan -u https://example.com --mode bruteforce
```

**Hybrid mode**: Starts with stealthy scan, then uses brute-force for remaining plugins
```bash
wpprobe scan -u https://example.com --mode hybrid
```

### Output Options

Save results to CSV:
```bash
wpprobe scan -u https://example.com -o results.csv
```

Save results to JSON:
```bash
wpprobe scan -u https://example.com -o results.json
```

### Advanced Options

**Custom plugin list** (for brute-force/hybrid modes):
```bash
wpprobe scan -u https://example.com --mode bruteforce --plugin-list my-plugins.txt
```

**Custom HTTP headers**:
```bash
wpprobe scan -u https://example.com --header "User-Agent: CustomAgent" --header "X-Custom: value"
```

**Proxy configuration**:
```bash
wpprobe scan -u https://example.com --proxy http://proxy:8080
```

WPProbe also respects environment variables: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`.

**Rate limiting** (requests per second):
```bash
wpprobe scan -u https://example.com --rate-limit 10
```

**Thread count**:
```bash
wpprobe scan -f targets.txt -t 50
```

**Skip version checking**:
```bash
wpprobe scan -u https://example.com --no-check-version
```

### Search Vulnerabilities

Search vulnerabilities in the local database:

```bash
wpprobe search --cve CVE-2024-1234
wpprobe search --plugin woocommerce
wpprobe search --severity critical
wpprobe search --auth Unauth
wpprobe search --title "SQL Injection" --details
```

### List Database Statistics

Show vulnerability database statistics by severity:

```bash
wpprobe list
```

### Update WPProbe

Check for and update to the latest version:

```bash
wpprobe update
```

## How It Works

### Stealthy Mode

1. Fetches list of known WordPress plugins from precompiled database
2. Scans target site for exposed REST API routes (`?rest_route=/`)
3. Matches discovered endpoints with known plugin signatures
4. Retrieves installed version by extracting metadata from files like `readme.txt`
5. Correlates detected plugins with publicly known vulnerabilities (CVE mapping)
6. Outputs results in structured format (CSV or JSON)

This method generates fewer requests, faster scans, and lower chance of getting blocked by WAFs or security plugins.

### Brute-Force Mode

1. Loads comprehensive list of WordPress plugins (10k+ common plugins by default)
2. Checks for existence of each plugin by directly requesting its directory
3. Detects plugins based on HTTP response codes (non-404 responses indicate plugin exists)
4. Retrieves versions and checks for vulnerabilities
5. Outputs results in preferred format

### Hybrid Mode

1. Starts with stealthy scan using REST API endpoints
2. Records all plugins found via stealthy method
3. Continues with brute-force scan, skipping plugins already detected
4. Combines results from both methods for maximum detection coverage
5. Processes vulnerability information and outputs results

## Vulnerability Databases

WPProbe uses two vulnerability databases:

- **Wordfence**: Free and unlimited. Automatically updated via `update-db` command.
- **WPScan**: Requires Enterprise plan API token. Set `WPSCAN_API_TOKEN` environment variable. Downloads complete database exports (10000+ plugins) in a single request. **Note: WPScan integration has not been fully tested yet.**

## Output Formats

### CSV Format

```csv
URL,Plugin,Version,Severity,AuthType,CVEs,CVE Links,CVSS Score,CVSS Vector,Title
http://example.com,give,2.20.1,critical,Unauth,CVE-2025-22777,https://www.cve.org/CVERecord?id=CVE-2025-22777,9.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,GiveWP <= 3.19.3 - Unauthenticated PHP Object Injection
```

### JSON Format

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
                    "cve_link": "https://www.cve.org/CVERecord?id=CVE-2025-22777",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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

## Limitations

### Stealthy Mode

- Some plugins don't expose REST API endpoints, making them undetectable via this method
- If a plugin is outdated, disabled, or hidden by security plugins, it may not be detected
- Relies on a predefined plugin-to-endpoint mapping, which is regularly updated

### Brute-Force Mode

- Generates more HTTP requests, which may trigger security mechanisms or rate limits
- Less stealthy than REST API scanning as it directly probes for plugin directories
- Limited by the plugin list's comprehensiveness

### Hybrid Mode

- Still generates a significant number of requests after the stealthy phase
- May take longer to complete than pure stealthy mode

## Environment Variables

- `WPSCAN_API_TOKEN`: WPScan API token (required for WPScan database updates, Enterprise plan only)
- `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`: Proxy configuration
- `NO_PROXY`: Proxy bypass rules

## Commands Reference

- `wpprobe scan`: Scan WordPress sites for plugins and vulnerabilities
- `wpprobe update-db`: Update vulnerability databases (Wordfence and WPScan)
- `wpprobe search`: Search vulnerabilities by filters (CVE, plugin, severity, auth type, title)
- `wpprobe list`: Display vulnerability database statistics
- `wpprobe update`: Check for and update WPProbe to latest version

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## License

MIT License - see LICENSE file for details.

## Credits

Developed by @Chocapikk, inspired by modern recon methodologies and REST API enumeration techniques.

## Stats

<a href="https://star-history.com/#Chocapikk/wpprobe&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Chocapikk/wpprobe&type=Date" />
  </picture>
</a>
