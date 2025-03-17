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
	"reflect"
	"strings"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/charmbracelet/lipgloss"
)

func Test_buildPluginVulns(t *testing.T) {
	entries := []utils.PluginEntry{
		{Plugin: "plugin1", Severity: "critical", CVEs: []string{"CVE-1"}},
		{Plugin: "plugin1", Severity: "high", CVEs: []string{"CVE-2"}},
		{Plugin: "plugin2", Severity: "medium", CVEs: []string{"CVE-3"}},
	}
	got := buildPluginVulns(entries).Plugins
	want := map[string]VulnCategories{
		"plugin1": {
			Critical: []string{"CVE-1"},
			High:     []string{"CVE-2"},
		},
		"plugin2": {
			Medium: []string{"CVE-3"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildPluginVulns() = %v, want %v", got, want)
	}
}

func Test_buildPluginAuthGroups(t *testing.T) {
	entries := []utils.PluginEntry{
		{Plugin: "plugin1", Severity: "critical", CVEs: []string{"CVE-1"}, AuthType: "Unauth"},
		{Plugin: "plugin1", Severity: "critical", CVEs: []string{"CVE-2"}, AuthType: "Auth"},
		{Plugin: "plugin1", Severity: "high", CVEs: []string{"CVE-3"}, AuthType: "Unknown"},
	}
	got := buildPluginAuthGroups(entries).Plugins
	want := map[string]SeverityAuthGroup{
		"plugin1": {
			Severities: map[string]AuthGroup{
				"Critical": {AuthTypes: map[string][]string{
					"unauth": {"CVE-1"},
					"auth":   {"CVE-2"},
				}},
				"High": {AuthTypes: map[string][]string{
					"unknown": {"CVE-3"},
				}},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildPluginAuthGroups() = %v, want %v", got, want)
	}
}

func Test_buildSummaryLine(t *testing.T) {
	pluginVulns := map[string]VulnCategories{
		"plugin1": {
			Critical: []string{"CVE-1"},
			High:     []string{"CVE-2", "CVE-3"},
		},
		"plugin2": {
			Medium: []string{"CVE-4"},
		},
	}
	vulnTypes := []string{"Critical", "High", "Medium", "Low"}
	vulnStyles := map[string]lipgloss.Style{
		"Critical": lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("red")),
		"High":     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("yellow")),
		"Medium":   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("blue")),
		"Low":      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("green")),
	}
	line := buildSummaryLine("http://example.com", pluginVulns, vulnTypes, vulnStyles)
	if !strings.Contains(line, "Critical: 1") || !strings.Contains(line, "High: 2") ||
		!strings.Contains(line, "Medium: 1") {
		t.Errorf("buildSummaryLine() = %v, unexpected summary", line)
	}
}

func Test_sortedPluginsByConfidence(t *testing.T) {
	argsDetected := map[string]string{
		"pluginA": "1.0",
		"pluginB": "unknown",
		"pluginC": "2.0",
	}
	argsConfidence := map[string]*PluginData{
		"pluginA": {Confidence: 90.0},
		"pluginB": {Confidence: 60.0},
		"pluginC": {Confidence: 80.0},
	}
	argsVulns := map[string]VulnCategories{
		"pluginA": {Critical: []string{"CVE-2023-1111"}},
		"pluginB": {},
		"pluginC": {High: []string{"CVE-2022-5678"}},
	}

	got := sortedPluginsByConfidence(argsDetected, argsConfidence, argsVulns)

	want := []string{"pluginA", "pluginC", "pluginB"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("sortedPluginsByConfidence() = %v, want %v", got, want)
	}
}

func Test_formatPluginLabel(t *testing.T) {
	tests := []struct {
		name       string
		plugin     string
		version    string
		confidence float64
		ambiguous  bool
		want       string
	}{
		{"KnownVersion", "plugin", "1.0", 90.0, false, "plugin (1.0)"},
		{
			"UnknownVersion",
			"plugin",
			"unknown",
			75.0,
			false,
			"plugin (unknown) [75.00% confidence]",
		},
		{"Ambiguous", "plugin", "1.0", 90.0, true, "plugin (1.0) [90.00% confidence] ⚠️"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPluginLabel(tt.plugin, tt.version, tt.confidence, tt.ambiguous); got != tt.want {
				t.Errorf("formatPluginLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPluginColor(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		vulnCategories VulnCategories
		exists         bool
		want           lipgloss.Style
	}{
		{
			"CriticalVuln",
			"1.0",
			VulnCategories{Critical: []string{"CVE-2023-1111"}},
			true,
			criticalStyle,
		},
		{"NoVuln", "1.0", VulnCategories{}, true, noVulnStyle},
		{"UnknownVersion", "unknown", VulnCategories{}, false, noVersionStyle},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPluginColor(tt.version, tt.vulnCategories, tt.exists)
			if got.Render("test") != tt.want.Render("test") {
				t.Errorf(
					"getPluginColor() = %v, want %v",
					got.Render("test"),
					tt.want.Render("test"),
				)
			}
		})
	}
}
