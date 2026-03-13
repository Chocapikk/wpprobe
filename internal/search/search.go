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

package search

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/Chocapikk/wpprobe/internal/severity"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
	"github.com/charmbracelet/lipgloss/tree"
)

// FilterCriteria contains all filter criteria for searching vulnerabilities.
type FilterCriteria struct {
	CVE      string
	Plugin   string
	Title    string
	Severity string
	Auth     string
}

// AnyFilterSet checks if any filter in the criteria is set.
func AnyFilterSet(filters ...string) bool {
	for _, f := range filters {
		if f != "" {
			return true
		}
	}
	return false
}

// FilterAll filters vulnerabilities based on the provided criteria.
func FilterAll(
	vs []wordfence.Vulnerability,
	cve, slug, title, sev, auth string,
) []wordfence.Vulnerability {
	criteria := FilterCriteria{
		CVE:      cve,
		Plugin:   slug,
		Title:    title,
		Severity: sev,
		Auth:     auth,
	}
	return filterByCriteria(vs, criteria)
}

func filterByCriteria(vs []wordfence.Vulnerability, criteria FilterCriteria) []wordfence.Vulnerability {
	// Pre-lowercase criteria once to avoid repeated allocations per-vulnerability
	cveLower := strings.ToLower(criteria.CVE)
	pluginLower := strings.ToLower(criteria.Plugin)
	titleLower := strings.ToLower(criteria.Title)
	sevLower := strings.ToLower(criteria.Severity)
	authLower := strings.ToLower(criteria.Auth)

	out := make([]wordfence.Vulnerability, 0, len(vs))
	for _, v := range vs {
		if cveLower != "" && !strings.Contains(strings.ToLower(v.CVE), cveLower) {
			continue
		}
		if pluginLower != "" && !strings.Contains(strings.ToLower(v.Slug), pluginLower) {
			continue
		}
		if titleLower != "" && !strings.Contains(strings.ToLower(v.Title), titleLower) {
			continue
		}
		if sevLower != "" && strings.ToLower(v.Severity) != sevLower {
			continue
		}
		if authLower != "" && strings.ToLower(v.AuthType) != authLower {
			continue
		}
		out = append(out, v)
	}
	return out
}

// GroupByPlugin groups vulnerabilities by plugin slug.
func GroupByPlugin(vs []wordfence.Vulnerability) map[string][]wordfence.Vulnerability {
	m := make(map[string][]wordfence.Vulnerability)
	for _, v := range vs {
		m[v.Slug] = append(m[v.Slug], v)
	}
	return m
}

// BuildTree builds a tree structure for displaying search results.
func BuildTree(root *tree.Tree, byPlugin map[string][]wordfence.Vulnerability, showDetails bool) {
	slugs := sortedPluginSlugs(byPlugin)

	for _, slug := range slugs {
		list := byPlugin[slug]
		sortedList := sortVulnerabilitiesBySeverity(list)
		counts := countBySeverity(sortedList)

		pluginNode := buildPluginNode(slug, counts)
		pluginNode.Child(buildDownloadLink(slug))

		if showDetails {
			addSeverityDetails(pluginNode, sortedList)
		}

		root.Child(pluginNode)
	}
}

func sortedPluginSlugs(byPlugin map[string][]wordfence.Vulnerability) []string {
	slugs := make([]string, 0, len(byPlugin))
	for slug := range byPlugin {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs
}

func sortVulnerabilitiesBySeverity(list []wordfence.Vulnerability) []wordfence.Vulnerability {
	sorted := make([]wordfence.Vulnerability, len(list))
	copy(sorted, list)
	sort.Slice(sorted, func(i, j int) bool {
		return compareVulnerabilities(i, j, sorted)
	})
	return sorted
}

func compareVulnerabilities(i, j int, vulns []wordfence.Vulnerability) bool {
	a, b := vulns[i], vulns[j]
	aIdx := severity.IndexOf(severity.Order, strings.ToLower(a.Severity))
	bIdx := severity.IndexOf(severity.Order, strings.ToLower(b.Severity))
	if aIdx != bIdx {
		return aIdx < bIdx
	}
	return a.CVE < b.CVE
}

func countBySeverity(list []wordfence.Vulnerability) map[string]int {
	counts := severity.InitializeCounts()
	for _, v := range list {
		counts[severity.Normalize(v.Severity)]++
	}
	return counts
}

func buildPluginNode(slug string, counts map[string]int) *tree.Tree {
	label := formatPluginLabel(slug, counts)
	return tree.Root(label)
}

func formatPluginLabel(slug string, counts map[string]int) string {
	parts := []string{
		scanner.URLStyle.Render(slug),
		formatSeverityCount("C", "critical", counts),
		formatSeverityCount("H", "high", counts),
		formatSeverityCount("M", "medium", counts),
		formatSeverityCount("L", "low", counts),
		formatSeverityCount("U", "unknown", counts),
	}
	return strings.Join(parts, "  ")
}

func formatSeverityCount(abbrev, sev string, counts map[string]int) string {
	styleFunc := getSeverityStyle(sev)
	return fmt.Sprintf("%s:%d", styleFunc(abbrev), counts[sev])
}

func getSeverityStyle(sev string) func(string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return func(s string) string { return scanner.CriticalStyle.Render(s) }
	case "high":
		return func(s string) string { return scanner.HighStyle.Render(s) }
	case "medium":
		return func(s string) string { return scanner.MediumStyle.Render(s) }
	case "low":
		return func(s string) string { return scanner.LowStyle.Render(s) }
	default:
		return func(s string) string { return scanner.UnknownStyle.Render(s) }
	}
}

func buildDownloadLink(slug string) *tree.Tree {
	link := fmt.Sprintf("Download: https://wordpress.org/plugins/%s/", slug)
	return tree.Root(scanner.URLStyle.Render(link))
}

func addSeverityDetails(pluginNode *tree.Tree, list []wordfence.Vulnerability) {
	for _, sev := range severity.Order {
		entries := filterBySeverity(list, sev)
		if len(entries) == 0 {
			continue
		}
		sevLabel := fmt.Sprintf("%s (%d)", severityLabel(sev), len(entries))
		sevNode := tree.Root(sevLabel)
		for _, v := range entries {
			sevNode.Child(formatVulnerabilityEntry(v))
		}
		pluginNode.Child(sevNode)
	}
}

func filterBySeverity(vs []wordfence.Vulnerability, sev string) []wordfence.Vulnerability {
	sevLower := strings.ToLower(sev)
	out := make([]wordfence.Vulnerability, 0, len(vs)/4)
	for _, v := range vs {
		if strings.ToLower(v.Severity) != sevLower {
			continue
		}
		out = append(out, v)
	}
	return out
}

func severityLabel(sev string) string {
	lbl := severity.FormatTitleCase(sev)
	styleFunc := getSeverityStyle(sev)
	return styleFunc(lbl)
}

func formatVulnerabilityEntry(v wordfence.Vulnerability) string {
	cvss := formatCVSS(v.CVSSScore, v.Severity)
	auth := formatAuth(v.AuthType)
	title := truncateString(v.Title, 60)
	return fmt.Sprintf(
		"%s - %s | %s | Auth:%s CVSS:%s",
		v.CVE, v.CVELink, title, auth, cvss,
	)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatCVSS(score float64, sev string) string {
	s := fmt.Sprintf("%.1f", score)
	styleFunc := getSeverityStyle(sev)
	return styleFunc(s)
}

func formatAuth(auth string) string {
	authLower := severity.NormalizeAuth(auth)
	switch authLower {
	case "auth":
		return scanner.AuthStyle.Render("Auth")
	case "unauth":
		return scanner.UnauthStyle.Render("Unauth")
	case "privileged":
		return scanner.PrivilegedStyle.Render("Privileged")
	default:
		return scanner.UnknownStyle.Render(auth)
	}
}
