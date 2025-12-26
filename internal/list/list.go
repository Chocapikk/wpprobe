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

package list

import (
	"fmt"

	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/Chocapikk/wpprobe/internal/severity"
	"github.com/Chocapikk/wpprobe/internal/vulnerability"
	"github.com/charmbracelet/lipgloss/tree"
)

func RunList() error {
	vulns, err := vulnerability.LoadWordfenceVulnerabilities()
	if err != nil {
		return err
	}

	count := make(map[string]int)
	total := 0

	severities := make([]string, len(vulns))
	for i, v := range vulns {
		severities[i] = v.Severity
	}
	count = severity.CountBySeverity(severities)
	total = len(vulns)

	root := tree.Root(scanner.TitleStyle.Render("📊 CVE coverage database"))

	styles := map[string]func(string) string{
		"critical": func(s string) string { return scanner.CriticalStyle.Render(s) },
		"high":     func(s string) string { return scanner.HighStyle.Render(s) },
		"medium":   func(s string) string { return scanner.MediumStyle.Render(s) },
		"low":      func(s string) string { return scanner.LowStyle.Render(s) },
		"unknown":  func(s string) string { return scanner.UnknownStyle.Render(s) },
	}

	for _, sev := range severity.Order {
		if count[sev] == 0 {
			continue
		}
		capKey := severity.FormatTitleCase(sev)
		styleFunc := styles[sev]
		label := styleFunc(fmt.Sprintf("%-8s", capKey))
		root.Child(tree.Root(fmt.Sprintf("%s: %d", label, count[sev])))
	}

	root.Child(tree.Root(scanner.URLStyle.Render(
		fmt.Sprintf("Total detectable CVEs: %d", total),
	)))

	fmt.Println(scanner.SeparatorStyle.Render(root.String()))
	return nil
}
