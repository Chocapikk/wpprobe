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
	"strings"

	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
	"github.com/charmbracelet/lipgloss/tree"
)

func RunList() error {
	vulns, err := wordfence.LoadVulnerabilities("wordfence_vulnerabilities.json")
	if err != nil {
		return err
	}

	count := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"unknown":  0,
	}
	for _, v := range vulns {
		sev := strings.ToLower(v.Severity)
		if _, ok := count[sev]; !ok {
			sev = "unknown"
		}
		count[sev]++
	}

	total := 0
	for _, c := range count {
		total += c
	}

	root := tree.Root(scanner.TitleStyle.Render("📊 CVE coverage database"))

	type line struct {
		key   string
		style func(string) string
	}

	lines := []line{
		{"critical", func(s string) string { return scanner.CriticalStyle.Render(s) }},
		{"high", func(s string) string { return scanner.HighStyle.Render(s) }},
		{"medium", func(s string) string { return scanner.MediumStyle.Render(s) }},
		{"low", func(s string) string { return scanner.LowStyle.Render(s) }},
		{"unknown", func(s string) string { return scanner.UnknownStyle.Render(s) }},
	}

	for _, l := range lines {
		if count[l.key] == 0 {
			continue
		}
		capKey := strings.ToUpper(l.key[:1]) + l.key[1:]
		label := l.style(fmt.Sprintf("%-8s", capKey))
		root.Child(tree.Root(fmt.Sprintf("%s: %d", label, count[l.key])))
	}

	root.Child(tree.Root(scanner.URLStyle.Render(
		fmt.Sprintf("Total detectable CVEs: %d", total),
	)))

	fmt.Println(scanner.SeparatorStyle.Render(root.String()))
	return nil
}
