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
	"github.com/Chocapikk/wpprobe/internal/progress"
)

func getScanMode(mode string) string {
	if mode == "" {
		return "stealthy"
	}
	return mode
}

func performScan(ctx ScanExecutionContext, scanMode string) ([]string, PluginDetectionResult) {
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

func performStealthyScan(ctx ScanExecutionContext) ([]string, PluginDetectionResult) {
	setProgressMessage(ctx.Progress, isFileScan(ctx.Opts), "🔎 Discovering plugins from HTML...")

	htmlSlugs, err := discoverPluginsFromHTML(ctx.Target, ctx.Opts.Headers, ctx.Opts.Proxy, ctx.Opts.RateLimit)
	if err != nil {
		logger.DefaultLogger.Warning(fmt.Sprintf("HTML discovery failed on %s: %v", ctx.Target, err))
	}

	setProgressMessage(ctx.Progress, isFileScan(ctx.Opts), "🔎 Scanning REST API endpoints...")

	endpointsData, err := loadEndpointsData()
	if err != nil {
		return nil, PluginDetectionResult{}
	}

	endpoints := FetchEndpoints(ctx.Target, ctx.Opts.Headers, ctx.Opts.Proxy, ctx.Opts.RateLimit)

	resultCtx := DetectionResultContext{
		Endpoints:     endpoints,
		EndpointsData: endpointsData,
		HTMLSlugs:     htmlSlugs,
	}
	result := buildDetectionResult(resultCtx)

	if len(result.Detected) == 0 {
		return nil, result
	}
	return result.Detected, result
}

func performBruteforceScan(ctx ScanExecutionContext) ([]string, PluginDetectionResult) {
	plugins, err := LoadPluginsFromFile(ctx.Opts.PluginList)
	if err != nil {
		logger.DefaultLogger.Error("Failed to load plugin list: " + err.Error())
		return nil, PluginDetectionResult{}
	}

	progressCtx := BruteforceProgressContext{
		Opts:           ctx.Opts,
		ParentProgress: ctx.Progress,
		PluginCount:    len(plugins),
	}
	progress := setupBruteforceProgress(progressCtx)
	defer finishBruteforceProgress(progress, ctx.Opts)

	bruteReq := BruteforceRequest{
		Target:   ctx.Target,
		Plugins:  plugins,
		Threads:  ctx.Opts.Threads,
		Progress: progress,
		HTTP:     HTTPConfig{Headers: ctx.Opts.Headers, Proxy: ctx.Opts.Proxy, RateLimit: ctx.Opts.RateLimit},
	}
	detected := BruteforcePlugins(bruteReq)

	return buildBruteforceResult(detected)
}

func performHybridScan(ctx ScanExecutionContext) ([]string, PluginDetectionResult) {
	logger.DefaultLogger.Info("Starting hybrid scan: first stealthy, then brute-force...")

	stealthyList, stealthyRes := performStealthyScan(ctx)

	if len(stealthyList) == 0 {
		return performBruteforceScan(ctx)
	}

	finishProgressIfNeeded(ctx.Progress)

	remaining := calculateRemainingPlugins(stealthyList, ctx.Opts)
	if len(remaining) == 0 {
		return stealthyList, stealthyRes
	}

	brutefound := performBruteforceOnRemaining(ctx, remaining)

	resultCtx := HybridResultContext{
		StealthyList: stealthyList,
		StealthyRes:  stealthyRes,
		Brutefound:   brutefound,
	}
	return combineHybridResults(resultCtx)
}

func performBruteforceOnRemaining(ctx ScanExecutionContext, remaining []string) []string {
	var bruteBar *progress.ProgressManager
	if ctx.Opts.File == "" {
		bruteBar = progress.NewProgressBar(len(remaining), "🔎 Bruteforcing remaining")
		defer bruteBar.Finish()
	}

	bruteReq := BruteforceRequest{
		Target:   ctx.Target,
		Plugins:  remaining,
		Threads:  ctx.Opts.Threads,
		Progress: bruteBar,
		HTTP:     HTTPConfig{Headers: ctx.Opts.Headers, Proxy: ctx.Opts.Proxy, RateLimit: ctx.Opts.RateLimit},
	}
	return BruteforcePlugins(bruteReq)
}

