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

	"github.com/Chocapikk/wpprobe/internal/severity"
	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
)


func buildPluginVulns(resultsList []file.PluginEntry) PluginVulnerabilities {
	pluginVulns := PluginVulnerabilities{Plugins: make(map[string]VulnCategories)}
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

func buildPluginAuthGroups(resultsList []file.PluginEntry) PluginAuthGroups {
	pluginAuthGroups := PluginAuthGroups{Plugins: make(map[string]SeverityAuthGroup)}

	for _, entry := range resultsList {
		sevLabel := severity.FormatTitleCase(entry.Severity)

		if _, ok := pluginAuthGroups.Plugins[entry.Plugin]; !ok {
			pluginAuthGroups.Plugins[entry.Plugin] = SeverityAuthGroup{
				Severities: make(map[string]AuthGroup),
			}
		}

		if _, ok := pluginAuthGroups.Plugins[entry.Plugin].Severities[sevLabel]; !ok {
			pluginAuthGroups.Plugins[entry.Plugin].Severities[sevLabel] = AuthGroup{
				AuthTypes: make(map[string][]string),
			}
		}

		authKey := severity.NormalizeAuth(entry.AuthType)

		if len(entry.CVEs) > 0 {
			pluginAuthGroups.Plugins[entry.Plugin].Severities[sevLabel].AuthTypes[authKey] =
				append(
					pluginAuthGroups.Plugins[entry.Plugin].Severities[sevLabel].AuthTypes[authKey],
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
		"Critical": getCriticalCount,
		"High":     getHighCount,
		"Medium":   getMediumCount,
		"Low":      getLowCount,
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
		URLStyle.Render(target),
		strings.Join(summaryParts, " | "),
	)
}

func DisplayResults(ctx DisplayResultsContext) {
	if isFileScan(ctx.Opts) {
		return
	}
	if len(ctx.Detected) == 0 {
		fmt.Println(NoVulnStyle.Render("No plugins detected for target: " + ctx.Target))
		return
	}

	pv := buildPluginVulns(ctx.Results)
	pa := buildPluginAuthGroups(ctx.Results)

	if ctx.Progress != nil {
		ctx.Progress.RenderBlank()
	}

	vTypes := []string{"Critical", "High", "Medium", "Low"}
	vStyles := map[string]lipgloss.Style{
		"Critical": CriticalStyle,
		"High":     HighStyle,
		"Medium":   MediumStyle,
		"Low":      LowStyle,
	}

	summary := buildSummaryLine(ctx.Target, pv.Plugins, vTypes, vStyles)
	root := tree.Root(TitleStyle.Render(summary))

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

		for _, sev := range vTypes {
			sGrp, sOk := authGroups.Severities[sev]
			if !sOk {
				continue
			}

			sevNode := tree.Root(vStyles[sev].Render(sev))
			for _, key := range []string{"unauth", "auth", "privileged", "unknown"} {
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
					authNode.Child(strings.Join(cves[i:end], " ⋅ "))
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
				"⚠️ indicates that multiple plugins share common endpoints; only one of these is likely active.",
			),
		)
	}

	out := SeparatorStyle.Render(root.String())
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
		return AuthStyle.Render("Auth")
	case "unauth":
		return UnauthStyle.Render("Unauth")
	case "privileged":
		return PrivilegedStyle.Render("Privileged")
	default:
		return UnknownStyle.Render("Unknown")
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
		return NoVersionStyle
	case !ok:
		return NoVulnStyle
	case len(v.Critical) > 0:
		return CriticalStyle
	case len(v.High) > 0:
		return HighStyle
	case len(v.Medium) > 0:
		return MediumStyle
	case len(v.Low) > 0:
		return LowStyle
	default:
		return NoVulnStyle
	}
}

func getCriticalCount(v VulnCategories) int {
	return len(v.Critical)
}

func getHighCount(v VulnCategories) int {
	return len(v.High)
}

func getMediumCount(v VulnCategories) int {
	return len(v.Medium)
}

func getLowCount(v VulnCategories) int {
	return len(v.Low)
}

func comparePlugins(i, j int, plugins []PluginDisplayData) bool {
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
