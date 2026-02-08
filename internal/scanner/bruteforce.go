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
	sharedClient := req.HTTP.NewClient(10 * time.Second)
	sharedClient.EnableKeepAlives(req.Threads)
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
		Mu:       &mu,
		Wg:       &wg,
		Sem:      sem,
		Detected: &detected,
		Versions: &versions,
		Ctx:      ctx,
		Client:   sharedClient,
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
	defer recoverPanic("plugin " + plugin)

	select {
	case <-ctx.Ctx.Done():
		return
	default:
	}

	if ctx.Progress != nil {
		ctx.Progress.SetMessage(fmt.Sprintf("Bruteforcing plugin %-30.30s", plugin))
	}

	// Phase 1: quick HEAD check on plugin directory (403/200 = exists, 404 = skip)
	if !version.CheckPluginExists(ctx.Ctx, ctx.Client, ctx.Target, plugin) {
		incrementProgress(ctx.Progress)
		return
	}

	select {
	case <-ctx.Ctx.Done():
		return
	default:
	}

	// Phase 2: fetch readme.txt for version (only for plugins that exist)
	ver := version.GetPluginVersionWithClient(ctx.Ctx, ctx.Client, ctx.Target, plugin)
	if ver == "" || ver == "unknown" {
		ver = "unknown"
	}

	recordPluginFound(plugin, ver, ctx)
	incrementProgress(ctx.Progress)
}

func recordPluginFound(plugin, ver string, ctx BruteforceContext) {
	msg := "Found plugin " + plugin + " version " + ver
	if ctx.Progress != nil {
		_, _ = ctx.Progress.Bprintln(logger.FormatSuccess(msg))
	} else {
		logger.DefaultLogger.Success(msg)
	}

	ctx.Mu.Lock()
	*ctx.Detected = append(*ctx.Detected, plugin)
	(*ctx.Versions)[plugin] = ver
	ctx.Mu.Unlock()
}
