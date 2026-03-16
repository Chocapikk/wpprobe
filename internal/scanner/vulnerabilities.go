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

// CheckVulnerabilities checks vulnerabilities for detected plugins and themes.
func CheckVulnerabilities(req VulnerabilityCheckRequest) (map[string]string, []file.PluginEntry) {
	totalItems := len(req.Plugins) + len(req.Themes)
	entriesMap := make(map[string]string, totalItems)
	entriesList := make([]file.PluginEntry, 0, totalItems)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, req.Opts.Threads)

	if req.Progress != nil && req.Opts.File == "" {
		req.Progress.SetTotal(totalItems)
		req.Progress.SetMessage("🔎 Checking versions & vulnerabilities...")
	}

	vulnIndex := getOrBuildVulnerabilityIndex(req.Vulns)

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

	scanCtx := req.Ctx
	if scanCtx == nil {
		scanCtx = context.Background()
	}

	// Check plugins
	for _, slug := range req.Plugins {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
			go checkSoftwareVulnerabilities(slug, "plugin", req.Opts, checkCtx)
		case <-scanCtx.Done():
			wg.Done()
			goto done
		}
	}

	// Check themes
	for _, slug := range req.Themes {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
			go checkSoftwareVulnerabilities(slug, "theme", req.Opts, checkCtx)
		case <-scanCtx.Done():
			wg.Done()
			goto done
		}
	}

done:
	wg.Wait()
	return entriesMap, entriesList
}

var (
	cachedVulnIndex map[string][]*wordfence.Vulnerability
	cachedVulnSlice []wordfence.Vulnerability
	cachedVulnMu    sync.Mutex
)

// getOrBuildVulnerabilityIndex returns a cached index if the vulns slice hasn't changed,
// otherwise builds a new one. Since vulns come from a global cache, the pointer check works.
func getOrBuildVulnerabilityIndex(vulns []wordfence.Vulnerability) map[string][]*wordfence.Vulnerability {
	cachedVulnMu.Lock()
	defer cachedVulnMu.Unlock()

	if len(vulns) > 0 && len(cachedVulnSlice) > 0 && &vulns[0] == &cachedVulnSlice[0] {
		return cachedVulnIndex
	}

	cachedVulnIndex = buildVulnerabilityIndex(vulns)
	cachedVulnSlice = vulns
	return cachedVulnIndex
}

// vulnIndexKey builds a composite key "type:slug" to prevent collisions
// between plugins and themes that share the same slug.
func vulnIndexKey(softwareType, slug string) string {
	if softwareType == "" {
		softwareType = "plugin"
	}
	return softwareType + ":" + slug
}

// buildVulnerabilityIndex creates a map indexed by "type:slug" for fast lookup.
func buildVulnerabilityIndex(vulns []wordfence.Vulnerability) map[string][]*wordfence.Vulnerability {
	index := make(map[string][]*wordfence.Vulnerability)
	for i := range vulns {
		if vulns[i].Slug != "" {
			key := vulnIndexKey(vulns[i].SoftwareType, vulns[i].Slug)
			index[key] = append(index[key], &vulns[i])
		}
	}
	return index
}

func checkSoftwareVulnerabilities(
	slug string,
	softwareType string,
	opts ScanOptions,
	ctx VulnerabilityCheckContext,
) {
	defer ctx.Wg.Done()
	defer releaseSemaphore(ctx.Sem)
	defer recoverPanic(softwareType + " " + slug)

	version := getSoftwareVersion(slug, softwareType, opts, ctx)
	matched := findMatchingVulnerabilities(softwareType, slug, version, ctx.VulnIndex)
	local := buildSoftwareEntries(slug, softwareType, version, matched)

	ctx.Mu.Lock()
	(*ctx.EntriesMap)[slug] = version
	*ctx.EntriesList = append(*ctx.EntriesList, local...)
	ctx.Mu.Unlock()

	if opts.File == "" {
		incrementProgress(ctx.Progress)
	}
}

func getSoftwareVersion(slug, softwareType string, opts ScanOptions, ctx VulnerabilityCheckContext) string {
	if opts.NoCheckVersion {
		return "unknown"
	}
	if ctx.PreDetectedVersions != nil {
		if version, exists := ctx.PreDetectedVersions[slug]; exists {
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
	if softwareType == "theme" {
		return versionpkg.GetThemeVersionWithContext(scanCtx, ctx.Target, slug, cfg)
	}
	return versionpkg.GetPluginVersionWithContext(scanCtx, ctx.Target, slug, cfg)
}

func findMatchingVulnerabilities(
	softwareType string,
	slug string,
	version string,
	vulnIndex map[string][]*wordfence.Vulnerability,
) []*wordfence.Vulnerability {
	key := vulnIndexKey(softwareType, slug)
	vulns, exists := vulnIndex[key]
	if !exists || version == "" || version == "unknown" {
		return nil
	}

	matched := make([]*wordfence.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if versionpkg.IsVersionVulnerable(version, v.FromVersion, v.ToVersion) {
			matched = append(matched, v)
		}
	}
	return matched
}

func buildSoftwareEntries(
	slug string,
	softwareType string,
	version string,
	matched []*wordfence.Vulnerability,
) []file.PluginEntry {
	if len(matched) == 0 {
		return []file.PluginEntry{createSoftwareEntry(slug, softwareType, version, nil)}
	}

	seenCVEs := make(map[string]struct{}, len(matched))
	entries := make([]file.PluginEntry, 0, len(matched))

	for _, v := range matched {
		cve := v.CVE
		if cve == "" {
			cve = v.Title
		}
		if cve == "" {
			continue
		}
		if _, seen := seenCVEs[cve]; seen {
			continue
		}
		seenCVEs[cve] = struct{}{}
		entries = append(entries, createSoftwareEntry(slug, softwareType, version, v))
	}

	if len(entries) == 0 {
		return []file.PluginEntry{createSoftwareEntry(slug, softwareType, version, nil)}
	}

	return entries
}

// createSoftwareEntry builds a PluginEntry. If vuln is nil, creates an empty entry.
func createSoftwareEntry(slug, softwareType, version string, vuln *wordfence.Vulnerability) file.PluginEntry {
	if vuln == nil {
		return file.PluginEntry{
			Slug:       slug,
			SoftwareType: softwareType,
			Version:      version,
			CVEs:         []string{},
			Severity:     "none",
			AuthType:     "n/a",
		}
	}
	return file.PluginEntry{
		Slug:       slug,
		SoftwareType: softwareType,
		Version:      version,
		CVEs:         []string{vuln.CVE},
		CVELinks:     []string{vuln.CVELink},
		Severity:     vuln.Severity,
		AuthType:     vuln.AuthType,
		Title:        vuln.Title,
		CVSSScore:    vuln.CVSSScore,
		CVSSVector:   vuln.CVSSVector,
	}
}
