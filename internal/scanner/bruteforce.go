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
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Chocapikk/wpprobe/internal/http"
	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/progress"
	"github.com/Chocapikk/wpprobe/internal/version"
)

// BruteforcePlugins attempts to detect plugins by parsing their readme.txt for version.
// It updates the progress bar message with a fixed-width plugin name.
func BruteforcePlugins(req BruteforceRequest) ([]string, map[string]string) {
	if len(req.Plugins) == 0 {
		logger.DefaultLogger.Warning("No plugins provided for brute-force scan")
		return nil, make(map[string]string)
	}

	normalized := http.NormalizeURL(req.Target)
	var detected []string
	versions := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, req.Threads)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.DefaultLogger.Info("Interruption signal received, stopping bruteforce scan...")
		cancel()
	}()

	bruteCtx := BruteforceContext{
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
		Versions: &versions,
		Ctx:      ctx,
		Cancel:   cancel,
	}

pluginLoop:
	for _, plugin := range req.Plugins {
		if ctx.Err() != nil {
			logger.DefaultLogger.Info("Bruteforce scan interrupted, saving results...")
			break pluginLoop
		}

		wg.Add(1)
		select {
		case sem <- struct{}{}:
			go scanPlugin(plugin, bruteCtx)
		case <-ctx.Done():
			wg.Done()
			logger.DefaultLogger.Info("Bruteforce scan interrupted, saving results...")
			break pluginLoop
		}
	}

	if ctx.Err() != nil {
		logger.DefaultLogger.Info("Waiting for active goroutines to finish collecting results...")
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			logger.DefaultLogger.Info("All goroutines finished, displaying results...")
		case <-time.After(3 * time.Second):
			logger.DefaultLogger.Warning("Some goroutines did not finish in time, displaying partial results...")
		}
	} else {
		wg.Wait()
	}

	return detected, versions
}

// HybridScan performs a hybrid scan: first stealthy, then brute-forces remaining plugins.
func HybridScan(req HybridScanRequest) ([]string, map[string]string) {
	bruteReq := BruteforceRequest{
		Target:   req.Target,
		Threads:  req.Threads,
		Progress: req.Progress,
		HTTP:     req.HTTP,
	}

	if len(req.StealthyPlugins) == 0 {
		bruteReq.Plugins = req.BruteforcePlugins
		detected, versions := BruteforcePlugins(bruteReq)
		return detected, versions
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
	brutefound, versions := BruteforcePlugins(bruteReq)
	result := make([]string, len(req.StealthyPlugins), len(req.StealthyPlugins)+len(brutefound))
	copy(result, req.StealthyPlugins)
	return append(result, brutefound...), versions
}

func scanPlugin(plugin string, ctx BruteforceContext) {
	defer ctx.Wg.Done()
	defer releaseSemaphore(ctx.Sem)
	defer handlePanic(plugin)

	select {
	case <-ctx.Ctx.Done():
		return
	default:
	}

	updateProgressMessage(ctx.Progress, plugin)

	select {
	case <-ctx.Ctx.Done():
		return
	default:
		version := version.GetPluginVersionWithContext(ctx.Ctx, ctx.Target, plugin, ctx.HTTP.Headers, ctx.HTTP.Proxy, ctx.HTTP.RateLimit, ctx.HTTP.MaxRedirects)

		select {
		case <-ctx.Ctx.Done():
			return
		default:
		}

		if version == "" || version == "unknown" {
			incrementProgress(ctx.Progress)
			return
		}

		handlePluginFound(plugin, version, ctx.Progress, ctx.Mu, ctx.Detected, ctx.Versions, ctx.Cancel)
		incrementProgress(ctx.Progress)
	}
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
	versions *map[string]string,
	cancel context.CancelFunc,
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
	if versions != nil {
		(*versions)[plugin] = version
	}
	mu.Unlock()

	if cancel != nil {
		logger.DefaultLogger.Info("Plugin found, stopping bruteforce scan to display results...")
		cancel()
	}
}

func incrementProgress(progress *progress.ProgressManager) {
	if progress == nil {
		return
	}
	progress.Increment()
}
