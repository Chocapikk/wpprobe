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

package scanner

import (
	"context"
	"net/http"
	"sync"

	"github.com/Chocapikk/wpprobe/internal/file"
	wphttp "github.com/Chocapikk/wpprobe/internal/http"
	"github.com/Chocapikk/wpprobe/internal/progress"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

// ScanOptions contains all configuration options for scanning.
type ScanOptions struct {
	URL            string
	File           string
	NoCheckVersion bool
	Threads        int
	Output         string
	OutputFormat   string
	Verbose        bool
	ScanMode       string
	PluginList     string
	Headers        []string
	Proxy          string
	RateLimit      int             // Requests per second (0 = unlimited)
	MaxRedirects   int             // Maximum redirects to follow (0 = disable, -1 = default: 10)
	Context        context.Context // Context for cancellation
	HTTPClient     *http.Client    // External HTTP client (optional, for connection pooling)
}

// PluginData contains information about a detected plugin.
type PluginData struct {
	Score      int
	Confidence float64
	Ambiguous  bool
	Matches    []string
}

// PluginDetectionResult contains the results of plugin detection.
type PluginDetectionResult struct {
	Plugins  map[string]*PluginData
	Detected []string
}

// VulnCategories groups vulnerabilities by severity.
type VulnCategories struct {
	Critical []string
	High     []string
	Medium   []string
	Low      []string
}

// PluginVulnerabilities maps plugin names to their vulnerability categories.
type PluginVulnerabilities struct {
	Plugins map[string]VulnCategories
}

// PluginAuthGroups organizes vulnerabilities by plugin, severity, and auth type.
type PluginAuthGroups struct {
	Plugins map[string]SeverityAuthGroup
}

// SeverityAuthGroup groups vulnerabilities by severity and auth type.
type SeverityAuthGroup struct {
	Severities map[string]AuthGroup
}

// AuthGroup groups vulnerabilities by authentication type.
type AuthGroup struct {
	AuthTypes map[string][]string
}

// PluginDisplayData contains data for displaying plugin information.
type PluginDisplayData struct {
	name        string
	confidence  float64
	noVersion   bool
	hasCritical bool
	hasHigh     bool
	hasMedium   bool
	hasLow      bool
	hasVuln     bool
}

// HTTPConfigFromOpts builds an http.Config from ScanOptions.
func HTTPConfigFromOpts(opts ScanOptions) wphttp.Config {
	return wphttp.Config{
		Headers:        opts.Headers,
		Proxy:          opts.Proxy,
		RateLimit:      opts.RateLimit,
		MaxRedirects:   opts.MaxRedirects,
		ExternalClient: opts.HTTPClient,
	}
}

// ScanContext contains context for scanning operations.
type ScanContext struct {
	Target   string
	Threads  int
	HTTP     wphttp.Config
	Progress *progress.ProgressManager
}

// BruteforceRequest contains request parameters for bruteforce operations.
type BruteforceRequest struct {
	Target   string
	Plugins  []string
	Threads  int
	Progress *progress.ProgressManager
	HTTP     wphttp.Config
}

// HybridScanRequest contains request parameters for hybrid scan operations.
type HybridScanRequest struct {
	Target           string
	StealthyPlugins  []string
	BruteforcePlugins []string
	Threads          int
	Progress         *progress.ProgressManager
	HTTP             wphttp.Config
}

// BruteforceContext contains context for bruteforce operations.
type BruteforceContext struct {
	ScanContext
	Mu       *sync.Mutex
	Wg       *sync.WaitGroup
	Sem      chan struct{}
	Detected *[]string
	Versions *map[string]string
	Ctx      context.Context
	Client   *wphttp.HTTPClientManager
}

// VulnerabilityCheckRequest contains request parameters for checking vulnerabilities.
type VulnerabilityCheckRequest struct {
	Plugins  []string
	Target   string
	Vulns    []wordfence.Vulnerability
	Opts     ScanOptions
	Progress *progress.ProgressManager
	Versions map[string]string
	Ctx      context.Context // Context for cancellation
}

// VulnerabilityCheckContext contains context for vulnerability checking.
type VulnerabilityCheckContext struct {
	ScanContext
	Mu                  *sync.Mutex
	Wg                  *sync.WaitGroup
	Sem                 chan struct{}
	EntriesMap          *map[string]string
	EntriesList         *[]file.PluginEntry
	Vulnerabilities     []wordfence.Vulnerability
	VulnIndex           map[string][]*wordfence.Vulnerability // Indexed by plugin slug for fast lookup
	PreDetectedVersions map[string]string
	Ctx                 context.Context // Context for cancellation
}

// ScanExecutionConfig contains all configuration for executing multiple scans.
type ScanExecutionConfig struct {
	Targets  []string
	Opts     ScanOptions
	Vulns    []wordfence.Vulnerability
	Config   scanConfig
	Progress *progress.ProgressManager
	Writer   file.WriterInterface
}

// scanConfig contains internal scan configuration.
type scanConfig struct {
	perSite        int
	siteConcurrent int
	sem            chan struct{}
}

// ScanExecutionContext contains all context needed for executing a scan.
type ScanExecutionContext struct {
	Target   string
	Opts     ScanOptions
	Progress *progress.ProgressManager
	Ctx      context.Context
}

// ScanSiteContext contains all context needed for scanning a single site.
type ScanSiteContext struct {
	Target   string
	Opts     ScanOptions
	Writer   file.WriterInterface
	Progress *progress.ProgressManager
	Vulns    []wordfence.Vulnerability
}

// TargetScanContext contains context for scanning a single target.
type TargetScanContext struct {
	Target   string
	Opts     ScanOptions
	PerSite  int
	Writer   file.WriterInterface
	Progress *progress.ProgressManager
	Vulns    []wordfence.Vulnerability
	Sem      chan struct{}
	Wg       *sync.WaitGroup
}

// DisplayResultsContext contains context for displaying scan results.
type DisplayResultsContext struct {
	Target    string
	Detected  map[string]string
	PluginRes PluginDetectionResult
	Results   []file.PluginEntry
	Opts      ScanOptions
	Progress  *progress.ProgressManager
}

