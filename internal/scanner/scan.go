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

	vulns, _ := wordfence.LoadVulnerabilities("wordfence_vulnerabilities.json")
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
	sem := make(chan struct{}, siteThreads)
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			local := opts
			local.Threads = siteThreads
			ScanSite(t, local, writer, progress, vulns)

			if opts.File != "" && progress != nil {
				progress.Increment()
			}
		}(target)
	}
	wg.Wait()

	if progress != nil {
		progress.Finish()
	}
}

func performStealthyScan(
	target string,
	opts ScanOptions,
	progress *utils.ProgressManager,
) ([]string, PluginDetectionResult) {
	if progress != nil && opts.File == "" {
		progress.SetMessage("🔎 Scanning REST API endpoints...")
	}

	data, err := utils.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		utils.DefaultLogger.Error("Failed to load scanned_plugins.json: " + err.Error())
		return nil, PluginDetectionResult{}
	}
	endpointsData, err := LoadPluginEndpointsFromData(data)
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

	result := DetectPlugins(endpoints, endpointsData)
	if len(result.Detected) == 0 {
		return nil, result
	}
	return result.Detected, result
}

func performBruteforceScan(
	target string,
	opts ScanOptions,
	threads int,
	parentProgress *utils.ProgressManager,
) ([]string, PluginDetectionResult) {
	plugins, err := LoadPluginsFromFile(opts.PluginList)
	if err != nil {
		utils.DefaultLogger.Error("Failed to load plugin list: " + err.Error())
		return nil, PluginDetectionResult{}
	}

	var pb *utils.ProgressManager
	if parentProgress == nil {
		pb = utils.NewProgressBar(len(plugins), "🔎 Bruteforcing plugins...")
		defer pb.Finish()
	} else {
		pb = parentProgress
		if opts.File == "" {
			pb.SetTotal(len(plugins))
			pb.SetMessage("🔎 Bruteforcing plugins...")
		}
	}

	detected := BruteforcePlugins(target, plugins, threads, pb)

	pr := PluginDetectionResult{
		Plugins:  make(map[string]*PluginData, len(detected)),
		Detected: detected,
	}
	for _, p := range detected {
		pr.Plugins[p] = &PluginData{
			Score:      1,
			Confidence: 100.0,
			Ambiguous:  false,
			Matches:    []string{},
		}
	}
	return detected, pr
}

func performHybridScan(
	target string,
	opts ScanOptions,
	threads int,
	progress *utils.ProgressManager,
) ([]string, PluginDetectionResult) {
	utils.DefaultLogger.Info("Starting hybrid scan: first stealthy, then brute-force...")

	stealthyList, stealthyRes := performStealthyScan(target, opts, progress)

	if len(stealthyList) == 0 {
		return performBruteforceScan(target, opts, threads, progress)
	}

	if progress != nil {
		progress.Finish()
	}

	allPlugins, err := LoadPluginsFromFile(opts.PluginList)
	if err != nil {
		utils.DefaultLogger.Error("Failed to load plugin list: " + err.Error())
		return stealthyList, stealthyRes
	}
	seen := make(map[string]bool, len(stealthyList))
	for _, p := range stealthyList {
		seen[p] = true
	}
	var remaining []string
	for _, p := range allPlugins {
		if !seen[p] {
			remaining = append(remaining, p)
		}
	}

	var bruteBar *utils.ProgressManager
	if opts.File == "" {
		bruteBar = utils.NewProgressBar(len(remaining), "🔎 Bruteforcing remaining")
	}

	brutefound := BruteforcePlugins(target, remaining, threads, bruteBar)

	if bruteBar != nil {
		bruteBar.Finish()
	}

	combined := append([]string{}, stealthyList...)
	combined = append(combined, brutefound...)

	result := stealthyRes
	for _, p := range brutefound {
		result.Plugins[p] = &PluginData{
			Score:      1,
			Confidence: 100.0,
			Ambiguous:  false,
			Matches:    []string{},
		}
	}
	result.Detected = combined

	return combined, result
}

// ScanSite dispatches the chosen scan mode and displays results.
// The heavy lifting for each mode is delegated to helper functions.
func ScanSite(
	target string,
	opts ScanOptions,
	writer utils.WriterInterface,
	progress *utils.ProgressManager,
	vulns []wordfence.Vulnerability,
) {
	if opts.ScanMode == "" {
		opts.ScanMode = "stealthy"
	}

	if progress != nil {
		progress.ClearLine()
	}

	var (
		detected []string
		result   PluginDetectionResult
	)

	switch opts.ScanMode {
	case "stealthy":
		detected, result = performStealthyScan(target, opts, progress)

	case "bruteforce":
		detected, result = performBruteforceScan(target, opts, opts.Threads, progress)

	case "hybrid":
		detected, result = performHybridScan(target, opts, opts.Threads, progress)

	default:
		utils.DefaultLogger.Warning(
			"Unknown scan mode '" + opts.ScanMode + "', defaulting to stealthy",
		)
		detected, result = performStealthyScan(target, opts, progress)
	}

	if len(detected) == 0 {
		if progress != nil {
			progress.ClearLine()
		}
		if opts.File == "" {
			utils.DefaultLogger.Warning("No plugins detected on " + target)
		}
		if writer != nil {
			writer.WriteResults(target, []utils.PluginEntry{})
		}
		return
	}

	entriesMap := make(map[string]string, len(result.Detected))
	var entriesList []utils.PluginEntry

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, opts.Threads)

	if progress != nil && opts.File == "" {
		progress.SetTotal(len(result.Detected))
		progress.SetMessage("🔎 Checking versions & vulnerabilities...")
	}

	for _, plugin := range result.Detected {
		wg.Add(1)
		sem <- struct{}{}
		go func(pl string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			version := "unknown"
			if !opts.NoCheckVersion {
				version = utils.GetPluginVersion(target, pl, opts.Threads)
			}

			var matched []wordfence.Vulnerability
			for _, v := range vulns {
				if v.Slug == pl && utils.IsVersionVulnerable(version, v.FromVersion, v.ToVersion) {
					matched = append(matched, v)
				}
			}

			var local []utils.PluginEntry
			if len(matched) == 0 {
				local = append(local, utils.PluginEntry{
					Plugin:     pl,
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
				for _, v := range matched {
					local = append(local, utils.PluginEntry{
						Plugin:     pl,
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
			entriesMap[pl] = version
			entriesList = append(entriesList, local...)
			if progress != nil && opts.File == "" {
				progress.Increment()
			}
			mu.Unlock()
		}(plugin)
	}

	wg.Wait()

	if progress != nil {
		progress.ClearLine()
	}

	if writer != nil {
		writer.WriteResults(target, entriesList)
	}
	DisplayResults(target, entriesMap, result, entriesList, opts, progress)
}
