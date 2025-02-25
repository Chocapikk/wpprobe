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
}

func ScanTargets(opts ScanOptions) {
	var targets []string

	if opts.File != "" {
		lines, err := utils.ReadLines(opts.File)
		if err != nil {
			logger.Error("Failed to read file: " + err.Error())
			return
		}
		targets = lines
	} else {
		targets = append(targets, opts.URL)
	}

	siteThreads := int(math.Max(1, float64(opts.Threads)/float64(len(targets))))

	var progress *utils.ProgressManager
	if opts.File != "" {
		progress = utils.NewProgressBar(len(targets), "🔎 Scanning...")
	}

	var writer utils.WriterInterface
	if opts.Output != "" {
		writer = utils.GetWriter(opts.Output)
		defer writer.Close()
	}

	var wg sync.WaitGroup
	var mu sync.RWMutex
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
			ScanSite(t, localOpts, writer, progress)
			if progress != nil {
				mu.Lock()
				progress.Increment()
				mu.Unlock()
			}
		}(target, siteThreads)
	}

	wg.Wait()
	if progress != nil {
		progress.Finish()
	}
}

func ScanSite(
	target string,
	opts ScanOptions,
	writer utils.WriterInterface,
	progress *utils.ProgressManager,
) {
	data, err := utils.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		logger.Error("Failed to load scanned_plugins.json: " + err.Error())
		if progress != nil {
			progress.Increment()
		}
		return
	}

	pluginEndpoints, err := LoadPluginEndpointsFromData(data)
	if err != nil {
		logger.Error("Failed to parse scanned_plugins.json: " + err.Error())
		if progress != nil {
			progress.Increment()
		}
		return
	}

	endpoints := FetchEndpoints(target)
	if len(endpoints) == 0 {
		if opts.File == "" {
			logger.Warning("No REST endpoints found on " + target)
		}
		if progress != nil {
			progress.Increment()
		}
		return
	}

	pluginResult := DetectPlugins(endpoints, pluginEndpoints)
	if len(pluginResult.Detected) == 0 {
		if opts.File == "" {
			logger.Warning("No plugins detected on " + target)
		}
		if progress != nil {
			progress.Increment()
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

	vulnerabilityData, err := wordfence.LoadVulnerabilities("wordfence_vulnerabilities.json")
	if err != nil {
		logger.Warning("Failed to load Wordfence JSON: " + err.Error())
		logger.Info("Run 'wpprobe update-db' to fetch the latest vulnerability database.")
		logger.Warning("The scan will proceed, but vulnerabilities will not be displayed.")
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
					Plugin:   plugin,
					Version:  version,
					Severity: "None",
					CVEs:     []string{},
					Title:    "No vulnerabilities found",
					AuthType: "N/A",
				})
			} else {
				for _, v := range vulns {
					localResultsList = append(localResultsList, utils.PluginEntry{
						Plugin:   plugin,
						Version:  version,
						Severity: v.Severity,
						CVEs:     []string{v.CVE},
						Title:    v.Title,
						AuthType: v.AuthType,
					})
				}
			}

			mu.Lock()
			results[plugin] = version
			resultsList = append(resultsList, localResultsList...)
			mu.Unlock()
		}(plugin)
	}

	wg.Wait()

	if progress != nil {
		progress.Increment()
	}

	if writer != nil {
		writer.WriteResults(target, resultsList)
	}

	DisplayResults(target, results, pluginResult, resultsList, opts, progress)
}
