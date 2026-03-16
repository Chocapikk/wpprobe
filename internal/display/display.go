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

package display

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/Chocapikk/wpprobe/internal/severity"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
)

var vulnTypeOrder = []string{"Critical", "High", "Medium", "Low"}

var vulnTypeStyles = map[string]lipgloss.Style{
	"Critical": criticalStyle,
	"High":     highStyle,
	"Medium":   mediumStyle,
	"Low":      lowStyle,
}

var authTypeOrder = []string{"unauth", "auth", "privileged", "unknown"}

func buildPluginVulns(resultsList []file.PluginEntry) scanner.PluginVulnerabilities {
	pluginVulns := scanner.PluginVulnerabilities{Plugins: make(map[string]scanner.VulnCategories, len(resultsList))}
	for _, entry := range resultsList {
		sevNormalized := severity.Normalize(entry.Severity)
		cat := pluginVulns.Plugins[entry.Plugin]
		if len(entry.CVEs) > 0 {
			switch sevNormalized {
			case "critical":
				cat.Critical = append(cat.Critical, entry.CVEs[0])
			case "high":
				cat.High = append(cat.High, entry.CVEs[0])
			case "medium":
				cat.Medium = append(cat.Medium, entry.CVEs[0])
			case "low":
				cat.Low = append(cat.Low, entry.CVEs[0])
			}
		}
		pluginVulns.Plugins[entry.Plugin] = cat
	}
	return pluginVulns
}

func buildPluginAuthGroups(resultsList []file.PluginEntry) scanner.PluginAuthGroups {
	pluginAuthGroups := scanner.PluginAuthGroups{Plugins: make(map[string]scanner.SeverityAuthGroup, len(resultsList))}

	for _, entry := range resultsList {
		sevLabel := severity.FormatTitleCase(entry.Severity)

		pag, ok := pluginAuthGroups.Plugins[entry.Plugin]
		if !ok {
			pag = scanner.SeverityAuthGroup{Severities: make(map[string]scanner.AuthGroup, 4)}
			pluginAuthGroups.Plugins[entry.Plugin] = pag
		}

		ag, ok := pag.Severities[sevLabel]
		if !ok {
			ag = scanner.AuthGroup{AuthTypes: make(map[string][]string, 3)}
			pag.Severities[sevLabel] = ag
		}

		if len(entry.CVEs) > 0 {
			authKey := severity.NormalizeAuth(entry.AuthType)
			ag.AuthTypes[authKey] = append(ag.AuthTypes[authKey], entry.CVEs[0])
		}
	}
	return pluginAuthGroups
}

func buildSummaryLine(
	target string,
	pluginVulns map[string]scanner.VulnCategories,
	vulnTypes []string,
	vulnStyles map[string]lipgloss.Style,
) string {
	summaryParts := make([]string, 0, len(vulnTypes))
	for _, t := range vulnTypes {
		var total int
		for _, cat := range pluginVulns {
			switch t {
			case "Critical":
				total += len(cat.Critical)
			case "High":
				total += len(cat.High)
			case "Medium":
				total += len(cat.Medium)
			case "Low":
				total += len(cat.Low)
			}
		}
		summaryParts = append(summaryParts, fmt.Sprintf("%s: %d", vulnStyles[t].Render(t), total))
	}

	return fmt.Sprintf("%s (%s)",
		urlStyle.Render(target),
		strings.Join(summaryParts, " | "),
	)
}

// DisplayResults renders scan results to the terminal using lipgloss styling.
func DisplayResults(ctx scanner.DisplayResultsContext) {
	if ctx.Opts.File != "" && ctx.Opts.Output != "" {
		return
	}
	if len(ctx.Detected) == 0 {
		fmt.Println(noVulnStyle.Render("No plugins detected for target: " + ctx.Target))
		return
	}

	pv := buildPluginVulns(ctx.Results)
	pa := buildPluginAuthGroups(ctx.Results)

	if ctx.Progress != nil {
		ctx.Progress.RenderBlank()
	}

	summary := buildSummaryLine(ctx.Target, pv.Plugins, vulnTypeOrder, vulnTypeStyles)
	root := tree.Root(titleStyle.Render(summary))

	for _, plugin := range sortedPluginsByConfidence(ctx.Detected, ctx.PluginRes.Plugins, pv.Plugins) {
		version := ctx.Detected[plugin]
		conf := ctx.PluginRes.Plugins[plugin].Confidence
		ambiguous := ctx.PluginRes.Plugins[plugin].Ambiguous
		label := formatPluginLabel(plugin, version, conf, ambiguous)

		vulnCat, ok := pv.Plugins[plugin]
		plNode := tree.Root(getPluginColor(version, vulnCat, ok).Render(label))

		authGroups, hasAG := pa.Plugins[plugin]
		if !hasAG {
			root.Child(plNode)
			continue
		}

		for _, sev := range vulnTypeOrder {
			sGrp, sOk := authGroups.Severities[sev]
			if !sOk {
				continue
			}

			sevNode := tree.Root(vulnTypeStyles[sev].Render(sev))
			for _, key := range authTypeOrder {
				cves, cOk := sGrp.AuthTypes[key]
				if !cOk {
					continue
				}
				if len(cves) == 0 {
					continue
				}

				authNode := tree.Root(authLabel(key))
				for i := 0; i < len(cves); i += 4 {
					end := i + 4
					if end > len(cves) {
						end = len(cves)
					}
					authNode.Child(strings.Join(cves[i:end], " . "))
				}
				sevNode.Child(authNode)
			}
			plNode.Child(sevNode)
		}

		root.Child(plNode)
	}

	showWarning := false
	for _, pr := range ctx.PluginRes.Plugins {
		if len(pr.Matches) > 0 {
			showWarning = true
			break
		}
	}
	if showWarning {
		root.Child(
			tree.Root(
				"Warning: indicates that multiple plugins share common endpoints; only one of these is likely active.",
			),
		)
	}

	out := separatorStyle.Render(root.String())
	if ctx.Progress != nil {
		_, _ = ctx.Progress.Bprintln(out)
	} else {
		fmt.Println(out)
	}
}

func authLabel(k string) string {
	authLower := severity.NormalizeAuth(k)
	switch authLower {
	case "auth":
		return authStyle.Render("Auth")
	case "unauth":
		return unauthStyle.Render("Unauth")
	case "privileged":
		return privilegedStyle.Render("Privileged")
	default:
		return unknownStyle.Render("Unknown")
	}
}

type pluginDisplayData struct {
	name        string
	confidence  float64
	noVersion   bool
	hasCritical bool
	hasHigh     bool
	hasMedium   bool
	hasLow      bool
	hasVuln     bool
}

func sortedPluginsByConfidence(
	detectedPlugins map[string]string,
	pluginData map[string]*scanner.PluginData,
	pluginVulns map[string]scanner.VulnCategories,
) []string {

	plugins := make([]pluginDisplayData, 0, len(detectedPlugins))
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

		plugins = append(plugins, pluginDisplayData{
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
		return comparePlugins(i, j, plugins)
	})

	sorted := make([]string, len(plugins))
	for i, p := range plugins {
		sorted[i] = p.name
	}
	return sorted
}

func formatPluginLabel(p, v string, c float64, a bool) string {
	if a {
		return fmt.Sprintf("%s (%s) [%.2f%% confidence] Warning", p, v, c)
	} else if v == "unknown" {
		return fmt.Sprintf("%s (%s) [%.2f%% confidence]", p, v, c)
	} else {
		return fmt.Sprintf("%s (%s)", p, v)
	}
}

func getPluginColor(version string, v scanner.VulnCategories, ok bool) lipgloss.Style {
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

func comparePlugins(i, j int, plugins []pluginDisplayData) bool {
	a, b := plugins[i], plugins[j]
	if a.hasCritical != b.hasCritical {
		return a.hasCritical
	}
	if a.hasHigh != b.hasHigh {
		return a.hasHigh
	}
	if a.hasMedium != b.hasMedium {
		return a.hasMedium
	}
	if a.hasLow != b.hasLow {
		return a.hasLow
	}
	if a.noVersion != b.noVersion {
		return !a.noVersion
	}
	if a.confidence != b.confidence {
		return a.confidence > b.confidence
	}
	return a.name < b.name
}
