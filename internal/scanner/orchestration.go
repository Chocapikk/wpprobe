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
	"sync"

	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/vulnerability"
)

func ScanTargets(opts ScanOptions) {
	// Configure logger verbosity
	logger.DefaultLogger.Verbose = opts.Verbose

	targets := loadTargets(opts)
	if len(targets) == 0 {
		return
	}

	vulns, _ := vulnerability.LoadWordfenceVulnerabilities()
	config := buildScanConfig(opts, len(targets))
	progress := createProgressManager(opts, len(targets))
	writer := createWriter(opts)
	defer closeWriter(writer)

	execConfig := ScanExecutionConfig{
		Targets:  targets,
		Opts:     opts,
		Vulns:    vulns,
		Config:   config,
		Progress: progress,
		Writer:   writer,
	}
	executeScans(execConfig)
}

func executeScans(config ScanExecutionConfig) {
	var wg sync.WaitGroup
	for _, target := range config.Targets {
		wg.Add(1)
		config.Config.sem <- struct{}{}

		ctx := TargetScanContext{
			Target:   target,
			Opts:     config.Opts,
			PerSite:  config.Config.perSite,
			Writer:   config.Writer,
			Progress: config.Progress,
			Vulns:    config.Vulns,
			Sem:      config.Config.sem,
			Wg:       &wg,
		}
		go scanTarget(ctx)
	}

	wg.Wait()
	if config.Progress != nil {
		config.Progress.Finish()
	}
}

func scanTarget(ctx TargetScanContext) {
	defer ctx.Wg.Done()
	defer releaseSemaphore(ctx.Sem)
	defer recoverFromPanic()

	localOpts := ctx.Opts
	localOpts.Threads = ctx.PerSite

	siteCtx := ScanSiteContext{
		Target:   ctx.Target,
		Opts:     localOpts,
		Writer:   ctx.Writer,
		Progress: ctx.Progress,
		Vulns:    ctx.Vulns,
	}
	ScanSite(siteCtx)

	if ctx.Opts.File != "" && ctx.Progress != nil {
		ctx.Progress.Increment()
	}
}

func ScanSite(ctx ScanSiteContext) {
	scanMode := getScanMode(ctx.Opts.ScanMode)
	clearProgressLine(ctx.Progress, isFileScan(ctx.Opts))

	execCtx := ScanExecutionContext{
		Target:   ctx.Target,
		Opts:     ctx.Opts,
		Progress: ctx.Progress,
	}

	detected, result, versions := performScan(execCtx, scanMode)

	if len(detected) == 0 {
		handleNoPluginsDetected(ctx)
		return
	}

	vulnReq := VulnerabilityCheckRequest{
		Plugins:  result.Detected,
		Target:   ctx.Target,
		Vulns:    ctx.Vulns,
		Opts:     ctx.Opts,
		Progress: ctx.Progress,
		Versions: versions,
	}
	entriesMap, entriesList := CheckVulnerabilities(vulnReq)

	clearProgressLine(ctx.Progress, isFileScan(ctx.Opts))

	writeCtx := WriteResultsContext{
		Writer:  ctx.Writer,
		Target:  ctx.Target,
		Entries: entriesList,
	}
	writeResults(writeCtx)

	displayCtx := DisplayResultsContext{
		Target:    ctx.Target,
		Detected:  entriesMap,
		PluginRes: result,
		Results:   entriesList,
		Opts:      ctx.Opts,
		Progress:  ctx.Progress,
	}
	DisplayResults(displayCtx)
}
