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
	"github.com/Chocapikk/wpprobe/internal/wordfence"
	"github.com/charmbracelet/lipgloss/tree"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	titleCaser    = cases.Title(language.English)
	SeverityOrder = []string{"critical", "high", "medium", "low", "unknown"}
)

func AnyFilterSet(filters ...string) bool {
	for _, f := range filters {
		if f != "" {
			return true
		}
	}
	return false
}

func FilterAll(
	vs []wordfence.Vulnerability,
	cve, slug, title, sev, auth string,
) []wordfence.Vulnerability {
	out := make([]wordfence.Vulnerability, 0, len(vs))
	for _, v := range vs {
		if cve != "" && !strings.Contains(strings.ToLower(v.CVE), strings.ToLower(cve)) {
			continue
		}
		if slug != "" && !strings.Contains(strings.ToLower(v.Slug), strings.ToLower(slug)) {
			continue
		}
		if title != "" && !strings.Contains(strings.ToLower(v.Title), strings.ToLower(title)) {
			continue
		}
		if sev != "" && !strings.EqualFold(v.Severity, sev) {
			continue
		}
		if auth != "" && !strings.EqualFold(v.AuthType, auth) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func GroupByPlugin(vs []wordfence.Vulnerability) map[string][]wordfence.Vulnerability {
	m := make(map[string][]wordfence.Vulnerability)
	for _, v := range vs {
		m[v.Slug] = append(m[v.Slug], v)
	}
	return m
}

func BuildTree(root *tree.Tree, byPlugin map[string][]wordfence.Vulnerability, showDetails bool) {
	slugs := make([]string, 0, len(byPlugin))
	for slug := range byPlugin {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)

	for _, slug := range slugs {
		list := byPlugin[slug]
		sort.Slice(list, func(i, j int) bool {
			i1 := indexOf(SeverityOrder, strings.ToLower(list[i].Severity))
			j1 := indexOf(SeverityOrder, strings.ToLower(list[j].Severity))
			if i1 != j1 {
				return i1 < j1
			}
			return list[i].CVE < list[j].CVE
		})

		counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
		for _, v := range list {
			s := strings.ToLower(v.Severity)
			if _, ok := counts[s]; !ok {
				s = "unknown"
			}
			counts[s]++
		}

		label := fmt.Sprintf(
			"%s  %s:%d %s:%d %s:%d %s:%d %s:%d",
			scanner.URLStyle.Render(slug),
			scanner.CriticalStyle.Render("C"), counts["critical"],
			scanner.HighStyle.Render("H"), counts["high"],
			scanner.MediumStyle.Render("M"), counts["medium"],
			scanner.LowStyle.Render("L"), counts["low"],
			scanner.UnknownStyle.Render("U"), counts["unknown"],
		)
		pluginNode := tree.Root(label)
		pluginNode.Child(
			tree.Root(fmt.Sprintf("Download: https://wordpress.org/plugins/%s/", slug)),
		)

		if showDetails {
			for _, sev := range SeverityOrder {
				entries := filterBySeverity(list, sev)
				if len(entries) == 0 {
					continue
				}
				sevNode := tree.Root(severityLabel(sev))
				for _, v := range entries {
					cvss := formatCVSS(v.CVSSScore, v.Severity)
					auth := formatAuth(v.AuthType)
					sevNode.Child(fmt.Sprintf(
						"%s - %s [%s] Auth:%s CVSS:%s",
						v.CVE, v.CVELink, v.AffectedVersion, auth, cvss,
					))
				}
				pluginNode.Child(sevNode)
			}
		}

		root.Child(pluginNode)
	}
}

func filterBySeverity(vs []wordfence.Vulnerability, sev string) []wordfence.Vulnerability {
	out := make([]wordfence.Vulnerability, 0)
	for _, v := range vs {
		if strings.EqualFold(v.Severity, sev) {
			out = append(out, v)
		}
	}
	return out
}

func severityLabel(sev string) string {
	lbl := titleCaser.String(strings.ToLower(sev))
	switch strings.ToLower(sev) {
	case "critical":
		return scanner.CriticalStyle.Render(lbl)
	case "high":
		return scanner.HighStyle.Render(lbl)
	case "medium":
		return scanner.MediumStyle.Render(lbl)
	case "low":
		return scanner.LowStyle.Render(lbl)
	default:
		return scanner.UnknownStyle.Render(lbl)
	}
}

func formatCVSS(score float64, sev string) string {
	s := fmt.Sprintf("%.1f", score)
	switch strings.ToLower(sev) {
	case "critical":
		return scanner.CriticalStyle.Render(s)
	case "high":
		return scanner.HighStyle.Render(s)
	case "medium":
		return scanner.MediumStyle.Render(s)
	case "low":
		return scanner.LowStyle.Render(s)
	default:
		return scanner.UnknownStyle.Render(s)
	}
}

func formatAuth(auth string) string {
	switch strings.ToLower(auth) {
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

func indexOf(arr []string, s string) int {
	for i, v := range arr {
		if v == s {
			return i
		}
	}
	return len(arr)
}
