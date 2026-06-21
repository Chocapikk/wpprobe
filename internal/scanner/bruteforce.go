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

	fingerprints, err := LoadPluginFingerprints()
	if err != nil {
		logger.DefaultLogger.Warning(
			"Failed to load plugin fingerprints, falling back to directory probing: " + err.Error(),
		)
		fingerprints = map[string][]string{}
	}

	detected := make([]string, 0, len(req.Plugins)/10)
	versions := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, req.Threads)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			logger.DefaultLogger.Info("Interruption signal received, stopping bruteforce scan...")
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sigChan)
	}()

	// Learn what a request for a non-existent plugin file looks like on this
	// target, so detection works regardless of the web server and its config.
	calibrator := NewCalibrator(ctx, sharedClient, normalized)

	bruteCtx := BruteforceContext{
		ScanContext: ScanContext{
			Target:   normalized,
			Threads:  req.Threads,
			HTTP:     req.HTTP,
			Progress: req.Progress,
		},
		Mu:           &mu,
		Wg:           &wg,
		Sem:          sem,
		Detected:     &detected,
		Versions:     &versions,
		Ctx:          ctx,
		Client:       sharedClient,
		Fingerprints: fingerprints,
		Calibrator:   calibrator,
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

	detectedMap := make(map[string]struct{}, len(req.StealthyPlugins))
	for _, p := range req.StealthyPlugins {
		detectedMap[p] = struct{}{}
	}

	remaining := make([]string, 0, len(req.BruteforcePlugins))
	for _, p := range req.BruteforcePlugins {
		if _, exists := detectedMap[p]; !exists {
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

	// Phase 1: confirm the plugin is present on disk by probing the files it
	// ships (issue #27). A response that differs from the calibrated miss
	// baseline confirms the plugin, even when it is installed but not activated
	// (which the stealthy scan misses) and regardless of the web server config.
	if !probePluginFiles(ctx, plugin, candidateFiles(plugin, ctx.Fingerprints)) {
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

// candidateFiles returns the files to probe for a plugin slug: the curated
// fingerprint from the wordlist when one exists, otherwise a generic set
// covering the files almost every plugin ships (its main file, readme.txt and
// the "silence is golden" index.php). This lets a user pass a plain slug list
// (the historical --plugin-list format) without needing to know about per-file
// paths: the paths are reconstructed from the slug.
func candidateFiles(plugin string, fingerprints map[string][]string) []string {
	if files := fingerprints[plugin]; len(files) > 0 {
		return files
	}
	return []string{plugin + ".php", "readme.txt", "index.php"}
}

// probePluginFiles probes each candidate file for a plugin in priority order and
// returns true on the first response that differs from the target's calibrated
// "not found" baseline. Comparing against the baseline (instead of hardcoding
// "200 = found") is what makes detection reliable regardless of the web server:
// a file that exists is served (200) or executed (empty 200) or access-denied
// (403), all of which differ from how the host answers a missing path (a
// WordPress 301/404, or a soft-404 page). Requests do not follow redirects, so a
// canonical 301 to "<path>/" is seen as the miss signal it is.
func probePluginFiles(ctx BruteforceContext, plugin string, files []string) bool {
	base := ctx.Target + "/wp-content/plugins/" + plugin + "/"
	for _, f := range files {
		select {
		case <-ctx.Ctx.Done():
			return false
		default:
		}
		status, body, err := ctx.Client.ProbeNoRedirect(ctx.Ctx, base+f, probeBodyCap)
		if err != nil {
			continue
		}
		if ctx.Calibrator.IsInstalled(status, body) {
			return true
		}
	}
	return false
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
