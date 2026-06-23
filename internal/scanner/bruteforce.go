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
	forbidden := make([]string, 0)
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
		Forbidden:    &forbidden,
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

	// All probes are in; now that we can see how many slugs matched only via a
	// 403, decide whether they are real hardened plugins or WAF noise (issue #27).
	reconcileForbidden(bruteCtx, forbidden)

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
	found, status := probePluginFiles(ctx, plugin, candidateFiles(plugin, ctx.Fingerprints))
	if !found {
		incrementProgress(ctx.Progress)
		return
	}

	// A bare 403 is ambiguous: a plugin hardened with its own .htaccess and a WAF
	// forbidding the slug for a plugin that is NOT installed look identical here
	// (both forbid every file under <slug>/). Hold it and let reconcileForbidden
	// decide in aggregate after the scan, a few are kept as real hardened plugins,
	// an epidemic is suppressed as a WAF (issue #27). Version resolution is
	// deferred to the survivors so a WAF flood costs no extra readme.txt fetches.
	if status == 403 && ctx.Forbidden != nil {
		ctx.Mu.Lock()
		*ctx.Forbidden = append(*ctx.Forbidden, plugin)
		ctx.Mu.Unlock()
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
// returns true (with the confirming HTTP status) on the first response that
// differs from the target's calibrated "not found" baseline. Comparing against
// the baseline (instead of hardcoding "200 = found") is what makes detection
// reliable regardless of the web server: a file that exists is served (200) or
// executed (empty 200) or access-denied (403), all of which differ from how the
// host answers a missing path (a WordPress 301/404, or a soft-404 page).
// Requests do not follow redirects, so a canonical 301 to "<path>/" is seen as
// the miss signal it is. The confirming status is returned so the caller can
// treat a bare 403 (ambiguous between a hardened plugin and a WAF) differently
// from a served response (issue #27).
func probePluginFiles(ctx BruteforceContext, plugin string, files []string) (bool, int) {
	base := ctx.Target + "/wp-content/plugins/" + plugin + "/"
	for _, f := range files {
		select {
		case <-ctx.Ctx.Done():
			return false, 0
		default:
		}
		status, body, err := ctx.Client.ProbeNoRedirect(ctx.Ctx, base+f, probeBodyCap)
		if err != nil {
			continue
		}
		if ctx.Calibrator.IsInstalled(status, body) {
			return true, status
		}
	}
	return false, 0
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

// forbiddenWAFThreshold is the number of 403-only matches above which they are
// treated as a WAF or global 403 policy rather than real .htaccess-hardened
// plugins, and suppressed. A normal host rarely hardens more than a handful of
// individual plugins this way, and a blanket deny over the whole plugins
// directory is already absorbed by calibration (the random calibration probes
// get the same 403, so it becomes the miss baseline). A host that forbids more
// distinct slugs than this is filtering by name/pattern, not running them all
// (issue #27).
const forbiddenWAFThreshold = 5

// reconcileForbidden decides what to do with the slugs that matched only via a
// 403, now that the whole scan is done and their count is known. At or below the
// threshold they are plausibly real plugins hardened with their own .htaccess and
// are reported (resolving each version now, which a streaming hit would have done
// inline). Above it, the host is forbidding plugin paths wholesale, so they are
// dropped with a single warning instead of flooding the output with false
// positives (issue #27). The count of dropped matches is logged, never silently
// swallowed.
func reconcileForbidden(ctx BruteforceContext, forbidden []string) {
	if len(forbidden) == 0 {
		return
	}
	if len(forbidden) > forbiddenWAFThreshold {
		logger.DefaultLogger.Warning(fmt.Sprintf(
			"Suppressed %d plugin(s) that matched only with a 403: this host returns 403 for many plugin paths (likely a WAF or a global policy), so they are not reported as installed (issue #27).",
			len(forbidden)))
		return
	}
	for _, plugin := range forbidden {
		if ctx.Ctx.Err() != nil {
			return
		}
		ver := version.GetPluginVersionWithClient(ctx.Ctx, ctx.Client, ctx.Target, plugin)
		if ver == "" || ver == "unknown" {
			ver = "unknown"
		}
		recordPluginFound(plugin, ver, ctx)
	}
}
