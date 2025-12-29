// Copyright (c) 2025 Valentin Lobstein (Chocapikk) <balgogan@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Package wpprobe provides a public API for scanning WordPress sites for plugins and vulnerabilities.
package wpprobe

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/Chocapikk/wpprobe/internal/vulnerability"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
	"github.com/Chocapikk/wpprobe/internal/wpscan"
)

// Config holds configuration for a WordPress scan.
type Config struct {
	// Target URL to scan
	Target string

	// Scan mode: "stealthy", "bruteforce", or "hybrid"
	ScanMode string

	// Number of concurrent threads
	Threads int

	// Requests per second (0 = unlimited)
	RateLimit int

	// Custom HTTP headers (format: "Header: Value")
	Headers []string

	// Proxy URL (e.g., "http://proxy:8080")
	Proxy string

	// Maximum number of redirects to follow (0 = disable redirects, -1 = use default: 10)
	MaxRedirects int

	// Path to plugin list file (for bruteforce/hybrid modes)
	PluginList string

	// Skip version checking
	NoCheckVersion bool

	// Context for cancellation
	Context context.Context

	// Progress callback (optional)
	ProgressCallback func(message string, current, total int)

	// Enable verbose logging (default: false for API)
	Verbose bool

	// HTTPClient allows injecting an external HTTP client (e.g., from a connection pool).
	// If provided, wpprobe will use this client instead of creating its own.
	// The client should handle timeouts, TLS, and redirects as needed.
	HTTPClient *http.Client
}

// PluginResult represents a detected plugin with its vulnerabilities.
type PluginResult struct {
	// Plugin slug/name
	Name string

	// Detected version
	Version string

	// Confidence score (0-100)
	Confidence float64

	// Whether the detection is ambiguous
	Ambiguous bool

	// Vulnerabilities grouped by severity
	Vulnerabilities VulnerabilitiesBySeverity
}

// VulnerabilitiesBySeverity groups vulnerabilities by severity level.
type VulnerabilitiesBySeverity struct {
	Critical []Vulnerability
	High     []Vulnerability
	Medium   []Vulnerability
	Low      []Vulnerability
}

// Vulnerability represents a single vulnerability.
type Vulnerability struct {
	// CVE identifier (e.g., "CVE-2024-1234")
	CVE string

	// Title/description
	Title string

	// Severity: "critical", "high", "medium", "low"
	Severity string

	// Authentication type: "unauth", "privileged", "none"
	AuthType string

	// Affected version range
	AffectedVersion string

	// CVSS score (0-10)
	CVSSScore float64

	// CVSS vector string
	CVSSVector string
}

// ScanResult contains the complete scan results.
type ScanResult struct {
	// Target URL that was scanned
	Target string

	// Detected plugins
	Plugins []PluginResult

	// Total number of vulnerabilities found
	TotalVulnerabilities int

	// Summary by severity
	Summary VulnerabilitySummary
}

// VulnerabilitySummary provides a count of vulnerabilities by severity.
type VulnerabilitySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// Scanner is the main scanner instance.
// It uses the global vulnerability cache to avoid memory duplication.
type Scanner struct{}

// New creates a new Scanner instance.
// The scanner uses a global vulnerability cache that is loaded once and shared
// across all Scanner instances. This prevents memory bloat when creating many scanners.
// Logging is disabled during vulnerability loading when called from the API.
func New() (*Scanner, error) {
	// Disable verbose logging during vulnerability loading
	oldVerbose := logger.DefaultLogger.Verbose
	logger.DefaultLogger.Verbose = false
	defer func() {
		logger.DefaultLogger.Verbose = oldVerbose
	}()

	// Just trigger loading of the global cache (if not already loaded)
	// The actual data is stored globally and shared across all scanners
	_, _ = vulnerability.LoadWordfenceVulnerabilities()
	_, _ = vulnerability.LoadWPScanVulnerabilities()

	return &Scanner{}, nil
}

// Scan performs a WordPress scan with the given configuration.
func (s *Scanner) Scan(cfg Config) (*ScanResult, error) {
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}

	if cfg.ScanMode == "" {
		cfg.ScanMode = "stealthy"
	}

	if cfg.Threads == 0 {
		cfg.Threads = 10
	}

	if cfg.PluginList == "" {
		cfg.PluginList = "plugins.txt"
	}

	maxRedirects := cfg.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = -1 // Use default if not set
	}
	opts := scanner.ScanOptions{
		URL:            cfg.Target,
		ScanMode:       cfg.ScanMode,
		Threads:        cfg.Threads,
		RateLimit:      cfg.RateLimit,
		Headers:        cfg.Headers,
		Proxy:          cfg.Proxy,
		PluginList:     cfg.PluginList,
		NoCheckVersion: cfg.NoCheckVersion,
		MaxRedirects:   maxRedirects,
		File:           "api",        // Set File to disable progress bar display
		Verbose:        cfg.Verbose,  // Use Verbose from config (default: false)
		Context:        cfg.Context,  // Propagate context for cancellation
		HTTPClient:     cfg.HTTPClient, // Use external HTTP client if provided
	}

	writer := file.NewMemoryWriter()
	defer writer.Close()

	// Get vulnerabilities from global cache (no copy, just reference)
	vulns := vulnerability.GetAllVulnerabilities()

	scanCtx := scanner.ScanSiteContext{
		Target:   cfg.Target,
		Opts:     opts,
		Writer:   writer,
		Progress: nil, // No progress bar for API
		Vulns:    vulns,
	}

	scanner.ScanSite(scanCtx)

	entries := writer.GetResults()

	return s.buildResult(cfg.Target, entries), nil
}

// buildResult converts internal file entries to public API results.
// Only includes vulnerabilities for plugins with known versions (not "unknown" or empty).
// Deduplicates CVEs by severity level to avoid duplicates.
func (s *Scanner) buildResult(target string, entries []file.PluginEntry) *ScanResult {
	result := &ScanResult{
		Target:  target,
		Plugins: make([]PluginResult, 0),
		Summary: VulnerabilitySummary{},
	}

	pluginMap := make(map[string]*PluginResult)
	// Track seen CVEs per plugin per severity to deduplicate
	seenCVEs := make(map[string]map[string]map[string]bool) // plugin -> severity -> cve -> seen

	for _, entry := range entries {
		// Skip vulnerabilities if version is unknown or empty
		// We can't match CVEs to a specific version without knowing the version
		if entry.Version == "" || entry.Version == "unknown" {
			continue
		}

		plugin, exists := pluginMap[entry.Plugin]
		if !exists {
			plugin = &PluginResult{
				Name:           entry.Plugin,
				Version:        entry.Version,
				Confidence:     100.0,
				Ambiguous:      false,
				Vulnerabilities: VulnerabilitiesBySeverity{
					Critical: make([]Vulnerability, 0),
					High:     make([]Vulnerability, 0),
					Medium:   make([]Vulnerability, 0),
					Low:      make([]Vulnerability, 0),
				},
			}
			pluginMap[entry.Plugin] = plugin
			seenCVEs[entry.Plugin] = make(map[string]map[string]bool)
		}

		cve := ""
		if len(entry.CVEs) > 0 {
			cve = entry.CVEs[0]
		}

		// Skip if CVE is empty or already seen for this plugin/severity
		if cve == "" {
			continue
		}
		
		if seenCVEs[entry.Plugin][entry.Severity] == nil {
			seenCVEs[entry.Plugin][entry.Severity] = make(map[string]bool)
		}
		cveLower := strings.ToLower(cve)
		if seenCVEs[entry.Plugin][entry.Severity][cveLower] {
			continue
		}
		seenCVEs[entry.Plugin][entry.Severity][cveLower] = true

		vuln := Vulnerability{
			CVE:             cve,
			Title:           entry.Title,
			Severity:        entry.Severity,
			AuthType:        entry.AuthType,
			AffectedVersion: entry.Version,
			CVSSScore:       entry.CVSSScore,
			CVSSVector:      entry.CVSSVector,
		}

		switch entry.Severity {
		case "critical":
			plugin.Vulnerabilities.Critical = append(plugin.Vulnerabilities.Critical, vuln)
			result.Summary.Critical++
		case "high":
			plugin.Vulnerabilities.High = append(plugin.Vulnerabilities.High, vuln)
			result.Summary.High++
		case "medium":
			plugin.Vulnerabilities.Medium = append(plugin.Vulnerabilities.Medium, vuln)
			result.Summary.Medium++
		case "low":
			plugin.Vulnerabilities.Low = append(plugin.Vulnerabilities.Low, vuln)
			result.Summary.Low++
		}
	}

	// Only include plugins that have at least one vulnerability
	for _, plugin := range pluginMap {
		hasVulns := len(plugin.Vulnerabilities.Critical) > 0 ||
			len(plugin.Vulnerabilities.High) > 0 ||
			len(plugin.Vulnerabilities.Medium) > 0 ||
			len(plugin.Vulnerabilities.Low) > 0
		if hasVulns {
			result.Plugins = append(result.Plugins, *plugin)
		}
	}

	result.TotalVulnerabilities = result.Summary.Critical + result.Summary.High + result.Summary.Medium + result.Summary.Low

	return result
}

// UpdateDatabases updates both Wordfence and WPScan vulnerability databases.
// WPScan update requires WPSCAN_API_TOKEN environment variable to be set.
// Returns an error only if Wordfence update fails. WPScan update failures are ignored
// (WPScan is optional and requires Enterprise plan).
// Logging is disabled during database updates when called from the API.
func UpdateDatabases() error {
	// Disable verbose logging during database updates
	oldVerbose := logger.DefaultLogger.Verbose
	logger.DefaultLogger.Verbose = false
	defer func() {
		logger.DefaultLogger.Verbose = oldVerbose
	}()

	if err := wordfence.UpdateWordfence(); err != nil {
		return err
	}
	
	// WPScan update is optional - try it but don't fail if it errors
	_ = wpscan.UpdateWPScan()
	
	return nil
}

// Reload reloads vulnerabilities from the database files.
// Call this after UpdateDatabases() to use the newly downloaded data.
// Since all scanners share the global cache, this affects all Scanner instances.
func (s *Scanner) Reload() error {
	// Reset and reload the global cache
	vulnerability.ReloadVulnerabilityCache()

	// Trigger reload by accessing the cache
	_ = vulnerability.GetAllVulnerabilities()

	return nil
}


// DatabaseExists checks if the Wordfence vulnerability database file exists.
func DatabaseExists() bool {
	filePath, err := file.GetStoragePath("wordfence_vulnerabilities.json")
	if err != nil {
		return false
	}
	_, err = os.Stat(filePath)
	return err == nil
}

