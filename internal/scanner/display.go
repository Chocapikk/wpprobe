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

func buildPluginVulns(resultsList []utils.PluginEntry) map[string]VulnCategories {
	pluginVulns := make(map[string]VulnCategories)
	for _, entry := range resultsList {
		severity := cases.Title(language.Und, cases.NoLower).String(strings.ToLower(entry.Severity))
		cat := pluginVulns[entry.Plugin]
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
		pluginVulns[entry.Plugin] = cat
	}
	return pluginVulns
}

func buildPluginAuthGroups(
	resultsList []utils.PluginEntry,
) map[string]map[string]map[string][]string {
	pluginAuthGroups := make(map[string]map[string]map[string][]string)
	for _, entry := range resultsList {
		severity := cases.Title(language.Und, cases.NoLower).String(strings.ToLower(entry.Severity))
		if _, ok := pluginAuthGroups[entry.Plugin]; !ok {
			pluginAuthGroups[entry.Plugin] = make(map[string]map[string][]string)
		}
		if _, ok := pluginAuthGroups[entry.Plugin][severity]; !ok {
			pluginAuthGroups[entry.Plugin][severity] = make(map[string][]string)
		}

		authKey := strings.ToLower(entry.AuthType)
		if authKey != "auth" && authKey != "unauth" && authKey != "privileged" {
			authKey = "unknown"
		}

		if len(entry.CVEs) > 0 {
			pluginAuthGroups[entry.Plugin][severity][authKey] = append(
				pluginAuthGroups[entry.Plugin][severity][authKey],
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
	var summaryParts []string
	for _, t := range vulnTypes {
		count := 0
		for _, cat := range pluginVulns {
			switch t {
			case "Critical":
				count += len(cat.Critical)
			case "High":
				count += len(cat.High)
			case "Medium":
				count += len(cat.Medium)
			case "Low":
				count += len(cat.Low)
			}
		}
		summaryParts = append(summaryParts, fmt.Sprintf("%s: %d", vulnStyles[t].Render(t), count))
	}
	return fmt.Sprintf("🔎 %s (%s)", urlStyle.Render(target), strings.Join(summaryParts, " | "))
}

func DisplayResults(
	target string,
	detectedPlugins map[string]string,
	pluginResult PluginDetectionResult,
	resultsList []utils.PluginEntry,
	opts ScanOptions,
	progress *utils.ProgressManager,
) {
	vulnTypes := []string{"Critical", "High", "Medium", "Low"}
	vulnStyles := map[string]lipgloss.Style{
		"Critical": criticalStyle,
		"High":     highStyle,
		"Medium":   mediumStyle,
		"Low":      lowStyle,
	}

	if len(resultsList) == 0 {
		fmt.Println(noVulnStyle.Render("No vulnerabilities found for target: " + target))
		return
	}

	pluginVulns := buildPluginVulns(resultsList)
	pluginAuthGroups := buildPluginAuthGroups(resultsList)

	if progress != nil {
		progress.RenderBlank()
	}

	summaryLine := buildSummaryLine(target, pluginVulns, vulnTypes, vulnStyles)
	root := tree.Root(titleStyle.Render(summaryLine))

	for _, plugin := range sortedPluginsByConfidence(detectedPlugins, pluginResult.Confidence, pluginVulns) {
		version := detectedPlugins[plugin]
		confidence := pluginResult.Confidence[plugin]
		pluginLabel := formatPluginLabel(
			plugin,
			version,
			confidence,
			pluginResult.Ambiguity[plugin],
		)
		pluginNode := tree.Root(getPluginColor(version, pluginVulns[plugin]).Render(pluginLabel))

		if authGroups, ok := pluginAuthGroups[plugin]; ok {
			for _, severity := range vulnTypes {
				if groups, ok := authGroups[severity]; ok {
					severityNode := tree.Root(vulnStyles[severity].Render(severity))
					for _, key := range []string{"unauth", "auth", "privileged", "unknown"} {
						if cves, ok := groups[key]; ok && len(cves) > 0 {
							var label string
							switch key {
							case "unauth":
								label = unauthStyle.Render("Unauth")
							case "auth":
								label = authStyle.Render("Auth")
							case "privileged":
								label = privilegedStyle.Render("Privileged")
							default:
								label = unknownStyle.Render("Unknown")
							}
							authNode := tree.Root(label)
							for i := 0; i < len(cves); i += 4 {
								end := i + 4
								if end > len(cves) {
									end = len(cves)
								}
								authNode.Child(strings.Join(cves[i:end], " ⋅ "))
							}
							severityNode.Child(authNode)
						}
					}
					pluginNode.Child(severityNode)
				}
			}
		}

		root.Child(pluginNode)
	}

	if len(pluginResult.Ambiguity) > 0 {
		root.Child(
			tree.Root(
				"⚠️ indicates that multiple plugins share common endpoints; only one of these is likely active.",
			),
		)
	}

	encapsulatedResults := separatorStyle.Render(root.String())
	if progress != nil {
		progress.Bprintln(encapsulatedResults)
	} else {
		fmt.Println(encapsulatedResults)
	}
}

func sortedPluginsByConfidence(
	detectedPlugins map[string]string,
	pluginConfidence map[string]float64,
	pluginVulns map[string]VulnCategories,
) []string {
	type PluginData struct {
		name        string
		confidence  float64
		noVersion   bool
		hasCritical bool
		hasHigh     bool
		hasMedium   bool
		hasLow      bool
		hasVuln     bool
	}
	plugins := make([]PluginData, 0, len(detectedPlugins))

	for plugin, version := range detectedPlugins {
		noVersion := version == "unknown"
		vulns := pluginVulns[plugin]

		hasCritical := len(vulns.Critical) > 0
		hasHigh := len(vulns.High) > 0
		hasMedium := len(vulns.Medium) > 0
		hasLow := len(vulns.Low) > 0
		hasVuln := hasCritical || hasHigh || hasMedium || hasLow

		plugins = append(plugins, PluginData{
			name:        plugin,
			confidence:  pluginConfidence[plugin],
			noVersion:   noVersion,
			hasCritical: hasCritical,
			hasHigh:     hasHigh,
			hasMedium:   hasMedium,
			hasLow:      hasLow,
			hasVuln:     hasVuln,
		})
	}

	sort.Slice(plugins, func(i, j int) bool {
		if plugins[i].hasCritical && !plugins[j].hasCritical {
			return true
		}
		if !plugins[i].hasCritical && plugins[j].hasCritical {
			return false
		}

		if plugins[i].hasHigh && !plugins[j].hasHigh {
			return true
		}
		if !plugins[i].hasHigh && plugins[j].hasHigh {
			return false
		}

		if plugins[i].hasMedium && !plugins[j].hasMedium {
			return true
		}
		if !plugins[i].hasMedium && plugins[j].hasMedium {
			return false
		}

		if plugins[i].hasLow && !plugins[j].hasLow {
			return true
		}
		if !plugins[i].hasLow && plugins[j].hasLow {
			return false
		}

		if !plugins[i].noVersion && plugins[j].noVersion {
			return true
		}
		if plugins[i].noVersion && !plugins[j].noVersion {
			return false
		}

		if plugins[i].confidence != plugins[j].confidence {
			return plugins[i].confidence > plugins[j].confidence
		}

		return plugins[i].name < plugins[j].name
	})

	sortedPlugins := make([]string, len(plugins))
	for i, p := range plugins {
		sortedPlugins[i] = p.name
	}
	return sortedPlugins
}

func formatPluginLabel(plugin, version string, confidence float64, ambiguous bool) string {
	if ambiguous {
		return fmt.Sprintf("%s (%s) ⚠️", plugin, version)
	}
	if version == "unknown" {
		return fmt.Sprintf("%s (%s) [%.2f%% confidence]", plugin, version, confidence)
	}
	return fmt.Sprintf("%s (%s)", plugin, version)
}

func getPluginColor(version string, vulnCategories VulnCategories) lipgloss.Style {
	if version == "unknown" {
		return noVersionStyle
	} else if len(vulnCategories.Critical) > 0 {
		return criticalStyle
	} else if len(vulnCategories.High) > 0 {
		return highStyle
	} else if len(vulnCategories.Medium) > 0 {
		return mediumStyle
	} else if len(vulnCategories.Low) > 0 {
		return lowStyle
	}
	return noVulnStyle
}
