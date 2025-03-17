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
	"sort"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	bold           = lipgloss.NewStyle().Bold(true)
	urlStyle       = bold.Foreground(lipgloss.Color("#00FFFF"))
	titleStyle     = bold.Foreground(lipgloss.Color("#FFA500"))
	noVulnStyle    = bold.Foreground(lipgloss.Color("#00FF00"))
	noVersionStyle = bold.Foreground(lipgloss.Color("#808080"))
	criticalStyle  = bold.Foreground(lipgloss.Color("#FF0000"))
	highStyle      = bold.Foreground(lipgloss.Color("#FF4500"))
	mediumStyle    = bold.Foreground(lipgloss.Color("#FFA500"))
	lowStyle       = bold.Foreground(lipgloss.Color("#FFFF00"))

	separatorStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FFA500")).
			Padding(0, 2).
			Margin(1, 0)

	unauthStyle     = bold.Foreground(lipgloss.Color("#FF0000"))
	authStyle       = bold.Foreground(lipgloss.Color("#00FF00"))
	privilegedStyle = bold.Foreground(lipgloss.Color("#8A2BE2"))
	unknownStyle    = bold.Foreground(lipgloss.Color("#FFA500"))
)

type VulnCategories struct {
	Critical []string
	High     []string
	Medium   []string
	Low      []string
}

type PluginVulnerabilities struct {
	Plugins map[string]VulnCategories
}

type PluginAuthGroups struct {
	Plugins map[string]SeverityAuthGroup
}

type SeverityAuthGroup struct {
	Severities map[string]AuthGroup
}

type AuthGroup struct {
	AuthTypes map[string][]string
}

type PluginDisplayData struct {
	name        string
	confidence  float64
	noVersion   bool
	hasCritical bool
	hasHigh     bool
	hasMedium   bool
	hasLow      bool
	hasVuln     bool
}

func buildPluginVulns(resultsList []utils.PluginEntry) PluginVulnerabilities {
	pluginVulns := PluginVulnerabilities{Plugins: make(map[string]VulnCategories)}
	for _, entry := range resultsList {
		severity := cases.Title(language.Und, cases.NoLower).String(strings.ToLower(entry.Severity))
		cat := pluginVulns.Plugins[entry.Plugin]
		if len(entry.CVEs) > 0 {
			switch severity {
			case "Critical":
				cat.Critical = append(cat.Critical, entry.CVEs[0])
			case "High":
				cat.High = append(cat.High, entry.CVEs[0])
			case "Medium":
				cat.Medium = append(cat.Medium, entry.CVEs[0])
			case "Low":
				cat.Low = append(cat.Low, entry.CVEs[0])
			}
		}
		pluginVulns.Plugins[entry.Plugin] = cat
	}
	return pluginVulns
}

func buildPluginAuthGroups(resultsList []utils.PluginEntry) PluginAuthGroups {
	pluginAuthGroups := PluginAuthGroups{Plugins: make(map[string]SeverityAuthGroup)}

	for _, entry := range resultsList {
		severity := cases.Title(language.Und, cases.NoLower).String(strings.ToLower(entry.Severity))

		if _, ok := pluginAuthGroups.Plugins[entry.Plugin]; !ok {
			pluginAuthGroups.Plugins[entry.Plugin] = SeverityAuthGroup{
				Severities: make(map[string]AuthGroup),
			}
		}

		if _, ok := pluginAuthGroups.Plugins[entry.Plugin].Severities[severity]; !ok {
			pluginAuthGroups.Plugins[entry.Plugin].Severities[severity] = AuthGroup{
				AuthTypes: make(map[string][]string),
			}
		}

		authKey := strings.ToLower(entry.AuthType)
		if authKey != "auth" && authKey != "unauth" && authKey != "privileged" {
			authKey = "unknown"
		}

		if len(entry.CVEs) > 0 {
			pluginAuthGroups.Plugins[entry.Plugin].Severities[severity].AuthTypes[authKey] =
				append(
					pluginAuthGroups.Plugins[entry.Plugin].Severities[severity].AuthTypes[authKey],
					entry.CVEs[0],
				)
		}
	}
	return pluginAuthGroups
}

func buildSummaryLine(
	target string,
	pluginVulns map[string]VulnCategories,
	vulnTypes []string,
	vulnStyles map[string]lipgloss.Style,
) string {
	getCount := map[string]func(VulnCategories) int{
		"Critical": func(v VulnCategories) int { return len(v.Critical) },
		"High":     func(v VulnCategories) int { return len(v.High) },
		"Medium":   func(v VulnCategories) int { return len(v.Medium) },
		"Low":      func(v VulnCategories) int { return len(v.Low) },
	}

	var summaryParts []string
	for _, t := range vulnTypes {
		var total int
		for _, cat := range pluginVulns {
			total += getCount[t](cat)
		}
		summaryParts = append(summaryParts, fmt.Sprintf("%s: %d", vulnStyles[t].Render(t), total))
	}

	return fmt.Sprintf("🔎 %s (%s)",
		urlStyle.Render(target),
		strings.Join(summaryParts, " | "),
	)
}

func DisplayResults(
	target string,
	detected map[string]string,
	pluginRes PluginDetectionResult,
	results []utils.PluginEntry,
	opts ScanOptions,
	progress *utils.ProgressManager,
) {
	if len(results) == 0 {
		fmt.Println(noVulnStyle.Render("No vulnerabilities found for target: " + target))
		return
	}

	pv := buildPluginVulns(results)
	pa := buildPluginAuthGroups(results)

	if progress != nil {
		progress.RenderBlank()
	}

	vTypes := []string{"Critical", "High", "Medium", "Low"}
	vStyles := map[string]lipgloss.Style{
		"Critical": criticalStyle,
		"High":     highStyle,
		"Medium":   mediumStyle,
		"Low":      lowStyle,
	}

	summary := buildSummaryLine(target, pv.Plugins, vTypes, vStyles)
	root := tree.Root(titleStyle.Render(summary))

	for _, plugin := range sortedPluginsByConfidence(detected, pluginRes.Plugins, pv.Plugins) {
		version := detected[plugin]
		conf := pluginRes.Plugins[plugin].Confidence
		label := formatPluginLabel(plugin, version, conf, pluginRes.Plugins[plugin].Ambiguous)

		vulnCat, ok := pv.Plugins[plugin]
		plNode := tree.Root(getPluginColor(version, vulnCat, ok).Render(label))

		authGroups, hasAG := pa.Plugins[plugin]
		if hasAG {
			for _, sev := range vTypes {
				sGrp, sOk := authGroups.Severities[sev]
				if !sOk {
					continue
				}
				sevNode := tree.Root(vStyles[sev].Render(sev))
				for _, key := range []string{"unauth", "auth", "privileged", "unknown"} {
					cves, cOk := sGrp.AuthTypes[key]
					if !cOk || len(cves) == 0 {
						continue
					}
					authNode := tree.Root(authLabel(key))
					for i := 0; i < len(cves); i += 4 {
						end := i + 4
						if end > len(cves) {
							end = len(cves)
						}
						authNode.Child(strings.Join(cves[i:end], " ⋅ "))
					}
					sevNode.Child(authNode)
				}
				plNode.Child(sevNode)
			}
		}
		root.Child(plNode)
	}

	if len(pluginRes.Detected) > 0 {
		root.Child(
			tree.Root(
				"⚠️ indicates that multiple plugins share common endpoints; only one of these is likely active.",
			),
		)
	}

	out := separatorStyle.Render(root.String())
	if progress != nil {
		progress.Bprintln(out)
	} else {
		fmt.Println(out)
	}
}

func authLabel(k string) string {
	switch k {
	case "unauth":
		return unauthStyle.Render("Unauth")
	case "auth":
		return authStyle.Render("Auth")
	case "privileged":
		return privilegedStyle.Render("Privileged")
	default:
		return unknownStyle.Render("Unknown")
	}
}

func sortedPluginsByConfidence(
	detectedPlugins map[string]string,
	pluginData map[string]*PluginData,
	pluginVulns map[string]VulnCategories,
) []string {

	var plugins []PluginDisplayData
	for plugin, version := range detectedPlugins {
		noVersion := version == "unknown"
		data := pluginData[plugin]
		vulns, existsV := pluginVulns[plugin]
		hc, hh, hm, hl := false, false, false, false
		if existsV {
			hc, hh, hm, hl = len(
				vulns.Critical,
			) > 0, len(
				vulns.High,
			) > 0, len(
				vulns.Medium,
			) > 0, len(
				vulns.Low,
			) > 0
		}

		plugins = append(plugins, PluginDisplayData{
			name:        plugin,
			confidence:  data.Confidence,
			noVersion:   noVersion,
			hasCritical: hc,
			hasHigh:     hh,
			hasMedium:   hm,
			hasLow:      hl,
			hasVuln:     hc || hh || hm || hl,
		})
	}

	sort.Slice(plugins, func(i, j int) bool {
		a, b := plugins[i], plugins[j]
		switch {
		case a.hasCritical != b.hasCritical:
			return a.hasCritical
		case a.hasHigh != b.hasHigh:
			return a.hasHigh
		case a.hasMedium != b.hasMedium:
			return a.hasMedium
		case a.hasLow != b.hasLow:
			return a.hasLow
		case a.noVersion != b.noVersion:
			return !a.noVersion
		case a.confidence != b.confidence:
			return a.confidence > b.confidence
		default:
			return a.name < b.name
		}
	})

	sorted := make([]string, len(plugins))
	for i, p := range plugins {
		sorted[i] = p.name
	}
	return sorted
}

func formatPluginLabel(p, v string, c float64, a bool) string {
	if a {
		return fmt.Sprintf("%s (%s) [%.2f%% confidence] ⚠️", p, v, c)
	} else if v == "unknown" {
		return fmt.Sprintf("%s (%s) [%.2f%% confidence]", p, v, c)
	} else {
		return fmt.Sprintf("%s (%s)", p, v)
	}
}

func getPluginColor(version string, v VulnCategories, ok bool) lipgloss.Style {
	switch {
	case version == "unknown":
		return noVersionStyle
	case !ok:
		return noVulnStyle
	case len(v.Critical) > 0:
		return criticalStyle
	case len(v.High) > 0:
		return highStyle
	case len(v.Medium) > 0:
		return mediumStyle
	case len(v.Low) > 0:
		return lowStyle
	default:
		return noVulnStyle
	}
}
