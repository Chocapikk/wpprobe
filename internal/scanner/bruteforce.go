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
	"sync"

	"github.com/Chocapikk/wpprobe/internal/http"
	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/progress"
	"github.com/Chocapikk/wpprobe/internal/version"
)

// BruteforcePlugins attempts to detect plugins by parsing their readme.txt for version.
// It updates the progress bar message with a fixed-width plugin name.
func BruteforcePlugins(req BruteforceRequest) []string {
	if len(req.Plugins) == 0 {
		logger.DefaultLogger.Warning("No plugins provided for brute-force scan")
		return nil
	}

	normalized := http.NormalizeURL(req.Target)
	var detected []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, req.Threads)

	ctx := BruteforceContext{
		ScanContext: ScanContext{
			Target:   normalized,
			Threads:  req.Threads,
			HTTP:     req.HTTP,
			Progress: req.Progress,
		},
		SyncContext: SyncContext{
			Mu:  &mu,
			Wg:  &wg,
			Sem: sem,
		},
		Detected: &detected,
	}

	for _, plugin := range req.Plugins {
		wg.Add(1)
		sem <- struct{}{}
		go scanPlugin(plugin, ctx)
	}

	wg.Wait()
	return detected
}

// HybridScan performs a hybrid scan: first stealthy, then brute-forces remaining plugins.
func HybridScan(req HybridScanRequest) []string {
	bruteReq := BruteforceRequest{
		Target:   req.Target,
		Threads:  req.Threads,
		Progress: req.Progress,
		HTTP:     req.HTTP,
	}

	if len(req.StealthyPlugins) == 0 {
		bruteReq.Plugins = req.BruteforcePlugins
		return BruteforcePlugins(bruteReq)
	}

	detectedMap := make(map[string]bool, len(req.StealthyPlugins))
	for _, p := range req.StealthyPlugins {
		detectedMap[p] = true
	}

	var remaining []string
	for _, p := range req.BruteforcePlugins {
		if !detectedMap[p] {
			remaining = append(remaining, p)
		}
	}

	bruteReq.Plugins = remaining
	brutefound := BruteforcePlugins(bruteReq)
	result := make([]string, len(req.StealthyPlugins), len(req.StealthyPlugins)+len(brutefound))
	copy(result, req.StealthyPlugins)
	return append(result, brutefound...)
}

func scanPlugin(plugin string, ctx BruteforceContext) {
	defer ctx.Wg.Done()
	defer releaseSemaphore(ctx.Sem)
	defer handlePanic(plugin)

	updateProgressMessage(ctx.Progress, plugin)

	version := version.GetPluginVersion(ctx.Target, plugin, ctx.HTTP.Headers, ctx.HTTP.Proxy, ctx.HTTP.RateLimit)
	if version == "" || version == "unknown" {
		incrementProgress(ctx.Progress)
		return
	}

	handlePluginFound(plugin, version, ctx.Progress, ctx.Mu, ctx.Detected)
	incrementProgress(ctx.Progress)
}

func handlePanic(plugin string) {
	if r := recover(); r != nil {
		logger.DefaultLogger.Error(
			fmt.Sprintf("Panic while scanning plugin %s: %v", plugin, r),
		)
	}
}

func updateProgressMessage(progress *progress.ProgressManager, plugin string) {
	if progress == nil {
		return
	}
	progress.SetMessage(fmt.Sprintf("🔎 Bruteforcing plugin %-30.30s", plugin))
}

func handlePluginFound(
	plugin string,
	version string,
	progress *progress.ProgressManager,
	mu *sync.Mutex,
	detected *[]string,
) {
	if progress != nil {
		progress.ClearLine()
	}
	logger.DefaultLogger.Info(fmt.Sprintf("Found plugin %s version %s", plugin, version))
	if progress != nil {
		progress.RenderBlank()
	}

	mu.Lock()
	*detected = append(*detected, plugin)
	mu.Unlock()
}

func incrementProgress(progress *progress.ProgressManager) {
	if progress == nil {
		return
	}
	progress.Increment()
}
