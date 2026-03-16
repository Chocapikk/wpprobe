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
	"fmt"

	"github.com/Chocapikk/wpprobe/internal/logger"
)

func getScanMode(mode string) string {
	if mode == "" {
		return "stealthy"
	}
	return mode
}

// ScanDetectionResult holds the combined results of plugin and theme detection.
type ScanDetectionResult struct {
	Plugins      []string
	Themes       []string
	PluginResult PluginDetectionResult
	Versions     map[string]string
}

func performScan(ctx ScanExecutionContext, scanMode string) ScanDetectionResult {
	switch scanMode {
	case "stealthy":
		return performStealthyScan(ctx)
	case "bruteforce":
		return performBruteforceScan(ctx)
	case "hybrid":
		return performHybridScan(ctx)
	default:
		logger.DefaultLogger.Warning(
			"Unknown scan mode '" + ctx.Opts.ScanMode + "', defaulting to stealthy",
		)
		return performStealthyScan(ctx)
	}
}

func performStealthyScan(ctx ScanExecutionContext) ScanDetectionResult {
	if ctx.Ctx != nil {
		select {
		case <-ctx.Ctx.Done():
			return ScanDetectionResult{}
		default:
		}
	}

	setProgressMessage(ctx.Progress, isFileScan(ctx.Opts), "Discovering plugins and themes from HTML...")

	httpCfg := HTTPConfigFromOpts(ctx.Opts)
	htmlResult, err := discoverFromHTML(ctx.Ctx, ctx.Target, httpCfg)
	if err != nil {
		if ctx.Ctx != nil && ctx.Ctx.Err() != nil {
			return ScanDetectionResult{}
		}
		logger.DefaultLogger.Warning(fmt.Sprintf("HTML discovery failed on %s: %v", ctx.Target, err))
	}

	if ctx.Ctx != nil {
		select {
		case <-ctx.Ctx.Done():
			return ScanDetectionResult{}
		default:
		}
	}

	setProgressMessage(ctx.Progress, isFileScan(ctx.Opts), "Scanning REST API endpoints...")

	endpointsData, err := loadEndpointsData()
	if err != nil {
		return ScanDetectionResult{Themes: htmlResult.Themes}
	}

	endpoints := FetchEndpoints(ctx.Ctx, ctx.Target, httpCfg)
	pluginResult := buildDetectionResult(endpoints, endpointsData, htmlResult.Plugins)

	return ScanDetectionResult{
		Plugins:      pluginResult.Detected,
		Themes:       htmlResult.Themes,
		PluginResult: pluginResult,
	}
}

func performBruteforceScan(ctx ScanExecutionContext) ScanDetectionResult {
	plugins, err := LoadPluginsFromFile(ctx.Opts.PluginList)
	if err != nil {
		logger.DefaultLogger.Error("Failed to load plugin list: " + err.Error())
		return ScanDetectionResult{}
	}

	progress := setupBruteforceProgress(ctx.Opts, ctx.Progress, len(plugins))
	defer finishBruteforceProgress(progress, ctx.Opts)

	bruteReq := BruteforceRequest{
		Target:   ctx.Target,
		Plugins:  plugins,
		Threads:  ctx.Opts.Threads,
		Progress: progress,
		HTTP:     HTTPConfigFromOpts(ctx.Opts),
	}
	detected, versions := BruteforcePlugins(bruteReq)

	detectedList, result := buildBruteforceResult(detected, versions)
	return ScanDetectionResult{Plugins: detectedList, PluginResult: result, Versions: versions}
}

func performHybridScan(ctx ScanExecutionContext) ScanDetectionResult {
	logger.DefaultLogger.Info("Starting hybrid scan: first stealthy, then brute-force...")

	stealthyResult := performStealthyScan(ctx)

	if len(stealthyResult.Plugins) == 0 {
		return performBruteforceScan(ctx)
	}

	finishProgressIfNeeded(ctx.Progress)

	remaining := calculateRemainingPlugins(stealthyResult.Plugins, ctx.Opts)
	if len(remaining) == 0 {
		return stealthyResult
	}

	brutefound, versions := performBruteforceOnRemaining(ctx, remaining)

	detected, result := combineHybridResults(stealthyResult.Plugins, stealthyResult.PluginResult, brutefound)
	return ScanDetectionResult{
		Plugins:      detected,
		Themes:       stealthyResult.Themes,
		PluginResult: result,
		Versions:     versions,
	}
}

func performBruteforceOnRemaining(ctx ScanExecutionContext, remaining []string) ([]string, map[string]string) {
	var bruteBar Progress
	if ctx.Opts.File == "" && ctx.Opts.NewProgress != nil {
		bruteBar = ctx.Opts.NewProgress(len(remaining), "Bruteforcing remaining")
		defer bruteBar.Finish()
	}

	bruteReq := BruteforceRequest{
		Target:   ctx.Target,
		Plugins:  remaining,
		Threads:  ctx.Opts.Threads,
		Progress: bruteBar,
		HTTP:     HTTPConfigFromOpts(ctx.Opts),
	}
	detected, versions := BruteforcePlugins(bruteReq)
	return detected, versions
}
