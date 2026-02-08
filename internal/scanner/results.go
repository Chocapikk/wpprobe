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
	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/logger"
)

func loadEndpointsData() (map[string][]string, error) {
	data, err := file.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		logger.DefaultLogger.Error("Failed to load scanned_plugins.json: " + err.Error())
		return nil, err
	}

	endpointsData, err := LoadPluginEndpointsFromData(data)
	if err != nil {
		logger.DefaultLogger.Error("Failed to parse scanned_plugins.json: " + err.Error())
		return nil, err
	}
	return endpointsData, nil
}

func buildDetectionResult(endpoints []string, endpointsData map[string][]string, htmlSlugs []string) PluginDetectionResult {
	var result PluginDetectionResult
	if len(endpoints) > 0 {
		result = DetectPlugins(endpoints, endpointsData)
	} else {
		result = PluginDetectionResult{
			Plugins:  make(map[string]*PluginData),
			Detected: nil,
		}
	}

	for _, slug := range htmlSlugs {
		if _, exists := result.Plugins[slug]; !exists {
			result.Plugins[slug] = &PluginData{
				Score:      1,
				Confidence: 50.0,
				Ambiguous:  false,
				Matches:    nil,
			}
			result.Detected = append(result.Detected, slug)
		}
	}
	return result
}

func buildBruteforceResult(detected []string, versions map[string]string) ([]string, PluginDetectionResult) {
	result := PluginDetectionResult{
		Plugins:  make(map[string]*PluginData, len(detected)),
		Detected: detected,
	}
	for _, p := range detected {
		result.Plugins[p] = &PluginData{
			Score:      1,
			Confidence: 100.0,
			Ambiguous:  false,
			Matches:    []string{},
		}
	}
	return detected, result
}

func calculateRemainingPlugins(stealthyList []string, opts ScanOptions) []string {
	allPlugins, err := LoadPluginsFromFile(opts.PluginList)
	if err != nil {
		logger.DefaultLogger.Error("Failed to load plugin list: " + err.Error())
		return nil
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
	return remaining
}

func combineHybridResults(stealthyList []string, stealthyRes PluginDetectionResult, brutefound []string) ([]string, PluginDetectionResult) {
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

func writeResults(writer file.WriterInterface, target string, entries []file.PluginEntry) {
	if writer != nil {
		writer.WriteResults(target, entries)
	}
}

func handleNoPluginsDetected(ctx ScanSiteContext) {
	clearProgressLine(ctx.Progress, isFileScan(ctx.Opts))
	if !isFileScan(ctx.Opts) {
		logger.DefaultLogger.Warning("No plugins detected on " + ctx.Target)
	}

	writeResults(ctx.Writer, ctx.Target, []file.PluginEntry{})
}

