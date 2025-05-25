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
	"math"
	"sync"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

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
}

func ScanTargets(opts ScanOptions) {
	var targets []string

	if opts.File != "" {
		lines, err := utils.ReadLines(opts.File)
		if err != nil {
			utils.DefaultLogger.Error("Failed to read file: " + err.Error())
			return
		}
		targets = lines
	} else {
		targets = append(targets, opts.URL)
	}

	vulnerabilityData, _ := wordfence.LoadVulnerabilities("wordfence_vulnerabilities.json")

	siteThreads := int(math.Max(1, float64(opts.Threads)/float64(len(targets))))

	var progress *utils.ProgressManager
	if opts.File != "" {
		progress = utils.NewProgressBar(len(targets), "🔎 Scanning...")
	} else {
		progress = utils.NewProgressBar(1, "🔎 Scanning...")
	}

	var writer utils.WriterInterface
	if opts.Output != "" {
		writer = utils.GetWriter(opts.Output)
		defer writer.Close()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Threads)

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string, scanThreads int) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			localOpts := opts
			localOpts.Threads = scanThreads

			ScanSite(t, localOpts, writer, progress, vulnerabilityData)

			if opts.File != "" && progress != nil {
				progress.Increment()
			}
		}(target, siteThreads)
	}

	wg.Wait()

	if progress != nil {
		progress.Finish()
	}
}

// performStealthyScan performs the original stealthy detection method using REST API endpoints
func performStealthyScan(target string, opts ScanOptions, progress *utils.ProgressManager) ([]string, PluginDetectionResult) {
	// Update progress message if available
	if progress != nil && opts.File == "" {
		progress.SetMessage("🔎 Scanning REST API endpoints...")
	}
	data, err := utils.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		utils.DefaultLogger.Error("Failed to load scanned_plugins.json: " + err.Error())
		return nil, PluginDetectionResult{}
	}

	pluginEndpoints, err := LoadPluginEndpointsFromData(data)
	if err != nil {
		utils.DefaultLogger.Error("Failed to parse scanned_plugins.json: " + err.Error())
		return nil, PluginDetectionResult{}
	}

	endpoints := FetchEndpoints(target)
	if len(endpoints) == 0 {
		if opts.File == "" {
			utils.DefaultLogger.Warning("No REST endpoints found on " + target)
		}
		return nil, PluginDetectionResult{}
	}

	pluginResult := DetectPlugins(endpoints, pluginEndpoints)
	if len(pluginResult.Detected) == 0 {
		return nil, pluginResult
	}

	return pluginResult.Detected, pluginResult
}

// performBruteforceScan performs a brute-force detection method using a plugin list
func performBruteforceScan(target string, opts ScanOptions, progress *utils.ProgressManager) ([]string, PluginDetectionResult) {
	plugins, err := LoadPluginsFromFile(opts.PluginList)
	if err != nil {
		utils.DefaultLogger.Error("Failed to load plugin list: " + err.Error())
		return nil, PluginDetectionResult{}
	}

	if progress != nil && opts.File == "" {
		progress.SetTotal(len(plugins))
		progress.SetMessage("🔎 Bruteforcing plugins...")
	}

	detected := BruteforcePlugins(target, plugins, opts.Threads, progress)

	// Create a fake PluginDetectionResult for consistency with other scan methods
	pluginResult := PluginDetectionResult{
		Plugins:  make(map[string]*PluginData),
		Detected: detected,
	}

	for _, plugin := range detected {
		pluginResult.Plugins[plugin] = &PluginData{
			Score:      1,
			Confidence: 100.0,
			Ambiguous:  false,
			Matches:    []string{},
		}
	}

	return detected, pluginResult
}

// performHybridScan performs a hybrid scan that first uses stealthy mode and then brute-force mode, skipping already found plugins
func performHybridScan(target string, opts ScanOptions, progress *utils.ProgressManager) ([]string, PluginDetectionResult) {
	utils.DefaultLogger.Info("Starting hybrid scan: first stealthy, then brute-force...")

	// First perform stealthy scan
	stealthyDetected, stealthyResult := performStealthyScan(target, opts, progress)

	// If stealthy scan found nothing, just do a full brute-force scan
	if len(stealthyDetected) == 0 {
		return performBruteforceScan(target, opts, progress)
	}

	// Get plugin list for brute-force
	plugins, err := LoadPluginsFromFile(opts.PluginList)
	if err != nil {
		utils.DefaultLogger.Error("Failed to load plugin list: " + err.Error())
		return stealthyDetected, stealthyResult
	}

	// Reset progress bar for brute-force phase
	if progress != nil && opts.File == "" {
		progress.SetTotal(len(plugins))
		progress.SetMessage("🔎 Hybrid scan: bruteforcing remaining plugins...")
	}

	// Perform hybrid scan
	allDetected := HybridScan(target, stealthyDetected, plugins, opts.Threads, progress)

	// Update the plugin result to include all detected plugins
	pluginResult := stealthyResult
	for _, plugin := range allDetected {
		if _, exists := pluginResult.Plugins[plugin]; !exists {
			pluginResult.Plugins[plugin] = &PluginData{
				Score:      1,
				Confidence: 100.0,
				Ambiguous:  false,
				Matches:    []string{},
			}
		}
	}
	pluginResult.Detected = allDetected

	return allDetected, pluginResult
}

func ScanSite(
	target string,
	opts ScanOptions,
	writer utils.WriterInterface,
	progress *utils.ProgressManager,
	vulnerabilityData []wordfence.Vulnerability,
) {
	// Default to stealthy mode if not specified
	if opts.ScanMode == "" {
		opts.ScanMode = "stealthy"
	}

	var detectedPlugins []string
	var pluginResult PluginDetectionResult

	switch opts.ScanMode {
	case "stealthy":
		// Original stealthy detection method using REST API endpoints
		detectedPlugins, pluginResult = performStealthyScan(target, opts, progress)

	case "bruteforce":
		// Brute-force detection method using plugin list
		detectedPlugins, pluginResult = performBruteforceScan(target, opts, progress)

	case "hybrid":
		// Hybrid mode: first stealthy, then brute-force skipping already found plugins
		detectedPlugins, pluginResult = performHybridScan(target, opts, progress)

	default:
		utils.DefaultLogger.Warning("Unknown scan mode '" + opts.ScanMode + "', defaulting to stealthy")
		detectedPlugins, pluginResult = performStealthyScan(target, opts, progress)
	}

	if len(detectedPlugins) == 0 {
		if opts.File == "" {
			utils.DefaultLogger.Warning("No plugins detected on " + target)
		}
		if writer != nil {
			writer.WriteResults(target, []utils.PluginEntry{})
		}
		return
	}

	results := make(map[string]string)
	var resultsList []utils.PluginEntry
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Threads)

	totalTasks := len(pluginResult.Detected)
	if progress != nil && opts.File == "" {
		progress.SetTotal(totalTasks)
	}

	for _, plugin := range pluginResult.Detected {
		wg.Add(1)
		sem <- struct{}{}
		go func(plugin string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			var localResultsList []utils.PluginEntry
			version := "unknown"
			if !opts.NoCheckVersion {
				version = utils.GetPluginVersion(target, plugin, opts.Threads)
			}

			vulns := []wordfence.Vulnerability{}
			for _, vuln := range vulnerabilityData {
				if vuln.Slug == plugin &&
					utils.IsVersionVulnerable(version, vuln.FromVersion, vuln.ToVersion) {
					vulns = append(vulns, vuln)
				}
			}

			if len(vulns) == 0 {
				localResultsList = append(localResultsList, utils.PluginEntry{
					Plugin:     plugin,
					Version:    version,
					Severity:   "N/A",
					AuthType:   "N/A",
					CVEs:       []string{"N/A"},
					CVELinks:   []string{"N/A"},
					Title:      "N/A",
					CVSSScore:  0.0,
					CVSSVector: "N/A",
				})
			} else {
				for _, v := range vulns {
					localResultsList = append(localResultsList, utils.PluginEntry{
						Plugin:     plugin,
						Version:    version,
						Severity:   v.Severity,
						AuthType:   v.AuthType,
						CVEs:       []string{v.CVE},
						CVELinks:   []string{v.CVELink},
						Title:      v.Title,
						CVSSScore:  v.CVSSScore,
						CVSSVector: v.CVSSVector,
					})
				}
			}

			mu.Lock()
			results[plugin] = version
			resultsList = append(resultsList, localResultsList...)

			if progress != nil && opts.File == "" {
				progress.Increment()
			}
			mu.Unlock()
		}(plugin)
	}

	wg.Wait()

	if writer != nil {
		writer.WriteResults(target, resultsList)
	}

	DisplayResults(target, results, pluginResult, resultsList, opts, progress)
}
