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
	"sync"

	"github.com/Chocapikk/wpprobe/internal/file"
	versionpkg "github.com/Chocapikk/wpprobe/internal/version"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

// CheckVulnerabilities checks vulnerabilities for detected plugins and returns entries.
func CheckVulnerabilities(req VulnerabilityCheckRequest) (map[string]string, []file.PluginEntry) {
	entriesMap := make(map[string]string, len(req.Plugins))
	var entriesList []file.PluginEntry

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, req.Opts.Threads)

	if req.Progress != nil && req.Opts.File == "" {
		req.Progress.SetTotal(len(req.Plugins))
		req.Progress.SetMessage("🔎 Checking versions & vulnerabilities...")
	}

	// Index vulnerabilities by slug for O(1) lookup instead of O(n) linear search
	vulnIndex := buildVulnerabilityIndex(req.Vulns)

	checkCtx := VulnerabilityCheckContext{
		ScanContext: ScanContext{
			Target:   req.Target,
			Threads:  req.Opts.Threads,
			HTTP:     HTTPConfigFromOpts(req.Opts),
			Progress: req.Progress,
		},
		Mu:                  &mu,
		Wg:                  &wg,
		Sem:                 sem,
		EntriesMap:          &entriesMap,
		EntriesList:         &entriesList,
		Vulnerabilities:     req.Vulns,
		VulnIndex:           vulnIndex,
		PreDetectedVersions: req.Versions,
		Ctx:                 req.Ctx,
	}

	for _, plugin := range req.Plugins {
		wg.Add(1)
		sem <- struct{}{}
		go checkPluginVulnerabilities(plugin, req.Opts, checkCtx)
	}

	wg.Wait()
	return entriesMap, entriesList
}

// buildVulnerabilityIndex creates a map of vulnerability pointers indexed by plugin slug for fast lookup.
func buildVulnerabilityIndex(vulns []wordfence.Vulnerability) map[string][]*wordfence.Vulnerability {
	index := make(map[string][]*wordfence.Vulnerability)
	for i := range vulns {
		if vulns[i].Slug != "" {
			index[vulns[i].Slug] = append(index[vulns[i].Slug], &vulns[i])
		}
	}
	return index
}

func checkPluginVulnerabilities(
	plugin string,
	opts ScanOptions,
	ctx VulnerabilityCheckContext,
) {
	defer ctx.Wg.Done()
	defer releaseSemaphore(ctx.Sem)
	defer recoverPanic("plugin " + plugin)

	version := getPluginVersion(plugin, opts, ctx, ctx.PreDetectedVersions)
	matched := findMatchingVulnerabilities(plugin, version, ctx.VulnIndex)
	local := buildPluginEntries(plugin, version, matched)

	// Prepare data before locking to minimize mutex hold time
	ctx.Mu.Lock()
	(*ctx.EntriesMap)[plugin] = version
	*ctx.EntriesList = append(*ctx.EntriesList, local...)
	ctx.Mu.Unlock()

	// Update progress outside of mutex lock
	if opts.File == "" {
		incrementProgress(ctx.Progress)
	}
}

func getPluginVersion(plugin string, opts ScanOptions, ctx VulnerabilityCheckContext, preDetectedVersions map[string]string) string {
	if opts.NoCheckVersion {
		return "unknown"
	}
	if preDetectedVersions != nil {
		if version, exists := preDetectedVersions[plugin]; exists {
			return version
		}
	}
	cfg := ctx.HTTP
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = -1
	}
	scanCtx := ctx.Ctx
	if scanCtx == nil {
		scanCtx = context.Background()
	}
	return versionpkg.GetPluginVersionWithContext(scanCtx, ctx.Target, plugin, cfg)
}

func findMatchingVulnerabilities(
	plugin string,
	version string,
	vulnIndex map[string][]*wordfence.Vulnerability,
) []*wordfence.Vulnerability {
	pluginVulns, exists := vulnIndex[plugin]
	if !exists || version == "" || version == "unknown" {
		return nil
	}

	var matched []*wordfence.Vulnerability
	for _, v := range pluginVulns {
		if versionpkg.IsVersionVulnerable(version, v.FromVersion, v.ToVersion) {
			matched = append(matched, v)
		}
	}
	return matched
}

func buildPluginEntries(
	plugin string,
	version string,
	matched []*wordfence.Vulnerability,
) []file.PluginEntry {
	if len(matched) == 0 {
		return []file.PluginEntry{createEmptyPluginEntry(plugin, version)}
	}

	seenCVEs := make(map[string]bool, len(matched))
	entries := make([]file.PluginEntry, 0, len(matched))

	for _, v := range matched {
		cve := v.CVE
		if cve == "" {
			cve = v.Title
		}
		if cve == "" || seenCVEs[cve] {
			continue
		}
		seenCVEs[cve] = true
		entries = append(entries, createVulnerablePluginEntry(plugin, version, v))
	}

	if len(entries) == 0 {
		return []file.PluginEntry{createEmptyPluginEntry(plugin, version)}
	}

	return entries
}

func createEmptyPluginEntry(plugin, version string) file.PluginEntry {
	return file.PluginEntry{
		Plugin:   plugin,
		Version:  version,
		CVEs:     []string{},
		Severity: "none",
		AuthType: "n/a",
	}
}

func createVulnerablePluginEntry(
	plugin string,
	version string,
	v *wordfence.Vulnerability,
) file.PluginEntry {
	return file.PluginEntry{
		Plugin:     plugin,
		Version:    version,
		CVEs:       []string{v.CVE},
		Severity:   v.Severity,
		AuthType:   v.AuthType,
		Title:      v.Title,
		CVSSScore:  v.CVSSScore,
		CVSSVector: v.CVSSVector,
	}
}

