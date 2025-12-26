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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package cmd

import (
	"fmt"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/Chocapikk/wpprobe/internal/search"
	"github.com/Chocapikk/wpprobe/internal/severity"
	"github.com/Chocapikk/wpprobe/internal/vulnerability"
	"github.com/charmbracelet/lipgloss/tree"
	"github.com/spf13/cobra"
)

var (
	flagCVE      string
	flagPlugin   string
	flagTitle    string
	flagSeverity string
	flagAuth     string
	showDetails  bool
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search vulnerabilities by various filters",
	RunE:  runSearch,
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().StringVar(&flagCVE, "cve", "", "Filter by CVE ID substring")
	searchCmd.Flags().StringVar(&flagPlugin, "plugin", "", "Filter by plugin slug substring")
	searchCmd.Flags().StringVar(&flagTitle, "title", "", "Filter by keyword in title")
	searchCmd.Flags().
		StringVar(&flagSeverity, "severity", "", "Filter by severity (critical, high, medium, low)")
	searchCmd.Flags().
		StringVar(&flagAuth, "auth", "", "Filter by auth type (Unauth, Auth, Privileged)")
	searchCmd.Flags().
		BoolVarP(&showDetails, "details", "d", false, "Show detailed CVE entries per plugin")
}

func runSearch(cmd *cobra.Command, args []string) error {
	if !search.AnyFilterSet(flagCVE, flagPlugin, flagTitle, flagSeverity, flagAuth) {
		errMsg := "please specify at least one filter: --cve, --plugin, --title, --severity, or --auth"
		logger.DefaultLogger.Error(errMsg)
		return fmt.Errorf(errMsg)
	}

	vulns, err := vulnerability.LoadWordfenceVulnerabilities()
	if err != nil {
		return err
	}

	filtered := search.FilterAll(vulns, flagCVE, flagPlugin, flagTitle, flagSeverity, flagAuth)
	if len(filtered) == 0 {
		fmt.Println(scanner.UnknownStyle.Render("No vulnerabilities match filters."))
		return nil
	}

	byPlugin := search.GroupByPlugin(filtered)
	summary := buildSearchSummary(filtered, byPlugin)

	root := tree.Root(scanner.TitleStyle.Render(summary))
	search.BuildTree(root, byPlugin, showDetails)

	fmt.Println(scanner.SeparatorStyle.Render(root.String()))
	return nil
}

func buildSearchSummary(filtered []vulnerability.Vulnerability, byPlugin map[string][]vulnerability.Vulnerability) string {
	totalVulns := len(filtered)
	totalPlugins := len(byPlugin)

	counts := countSeverities(filtered)
	parts := []string{
		fmt.Sprintf("🔍 %d vulnerabilities", totalVulns),
		fmt.Sprintf("%d plugins", totalPlugins),
		formatCountSummary(counts),
	}

	return strings.Join(parts, " | ")
}

func countSeverities(vulns []vulnerability.Vulnerability) map[string]int {
	severities := make([]string, len(vulns))
	for i, v := range vulns {
		severities[i] = v.Severity
	}
	return severity.CountBySeverity(severities)
}

func formatCountSummary(counts map[string]int) string {
	parts := []string{
		fmt.Sprintf("%s:%d", scanner.CriticalStyle.Render("C"), counts["critical"]),
		fmt.Sprintf("%s:%d", scanner.HighStyle.Render("H"), counts["high"]),
		fmt.Sprintf("%s:%d", scanner.MediumStyle.Render("M"), counts["medium"]),
		fmt.Sprintf("%s:%d", scanner.LowStyle.Render("L"), counts["low"]),
	}
	return strings.Join(parts, " ")
}
