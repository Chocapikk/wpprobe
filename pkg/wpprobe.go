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

	"github.com/Chocapikk/wpprobe/internal/file"
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
type Scanner struct {
	vulns []vulnerability.Vulnerability
}

// New creates a new Scanner instance.
// It loads vulnerabilities from the default databases (Wordfence and WPScan if configured).
// If databases are not available, it will continue with an empty vulnerability list.
func New() (*Scanner, error) {
	allVulns := []vulnerability.Vulnerability{}
	
	// Try to load Wordfence vulnerabilities, but don't fail if not available
	wordfenceVulns, err := vulnerability.LoadWordfenceVulnerabilities()
	if err == nil {
		allVulns = append(allVulns, wordfenceVulns...)
	}
	
	// Try to load WPScan vulnerabilities, but don't fail if not available
	wpscanVulns, err := vulnerability.LoadWPScanVulnerabilities()
	if err == nil {
		allVulns = append(allVulns, wpscanVulns...)
	}
	
	return &Scanner{vulns: allVulns}, nil
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
		File:           "api", // Set File to disable progress bar display
	}

	writer := file.NewMemoryWriter()
	defer writer.Close()

	scanCtx := scanner.ScanSiteContext{
		Target:   cfg.Target,
		Opts:     opts,
		Writer:   writer,
		Progress: nil, // No progress bar for API
		Vulns:    s.vulns,
	}

	scanner.ScanSite(scanCtx)

	entries := writer.GetResults()

	return s.buildResult(cfg.Target, entries), nil
}

// buildResult converts internal file entries to public API results.
func (s *Scanner) buildResult(target string, entries []file.PluginEntry) *ScanResult {
	result := &ScanResult{
		Target:  target,
		Plugins: make([]PluginResult, 0),
		Summary: VulnerabilitySummary{},
	}

	pluginMap := make(map[string]*PluginResult)

	for _, entry := range entries {
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
		}

		cve := ""
		if len(entry.CVEs) > 0 {
			cve = entry.CVEs[0]
		}
		vuln := Vulnerability{
			CVE:             cve,
			Title:           entry.Title,
			Severity:        entry.Severity,
			AuthType:        entry.AuthType,
			AffectedVersion: entry.Version,
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

	for _, plugin := range pluginMap {
		result.Plugins = append(result.Plugins, *plugin)
	}

	result.TotalVulnerabilities = result.Summary.Critical + result.Summary.High + result.Summary.Medium + result.Summary.Low

	return result
}

// UpdateDatabases updates both Wordfence and WPScan vulnerability databases.
// WPScan update requires WPSCAN_API_TOKEN environment variable to be set.
// Returns an error only if Wordfence update fails. WPScan update failures are ignored
// (WPScan is optional and requires Enterprise plan).
func UpdateDatabases() error {
	if err := wordfence.UpdateWordfence(); err != nil {
		return err
	}
	
	// WPScan update is optional - try it but don't fail if it errors
	_ = wpscan.UpdateWPScan()
	
	return nil
}

// Reload reloads vulnerabilities from the database files.
// Call this after UpdateDatabases() to use the newly downloaded data.
func (s *Scanner) Reload() error {
	allVulns := []vulnerability.Vulnerability{}
	
	// Try to load Wordfence vulnerabilities, but don't fail if not available
	wordfenceVulns, err := vulnerability.LoadWordfenceVulnerabilities()
	if err == nil {
		allVulns = append(allVulns, wordfenceVulns...)
	}
	
	// Try to load WPScan vulnerabilities, but don't fail if not available
	wpscanVulns, err := vulnerability.LoadWPScanVulnerabilities()
	if err == nil {
		allVulns = append(allVulns, wpscanVulns...)
	}
	
	s.vulns = allVulns
	return nil
}

