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
	"strconv"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

func makeVulns(n int) []wordfence.Vulnerability {
	sevs := []string{"critical", "high", "medium", "low"}
	auths := []string{"unauth", "auth", "privileged"}
	vulns := make([]wordfence.Vulnerability, n)
	for i := 0; i < n; i++ {
		vulns[i] = wordfence.Vulnerability{
			Title:       "SQL Injection in plugin-" + strconv.Itoa(i%100),
			Slug:        "plugin-" + strconv.Itoa(i%100),
			CVE:         "CVE-2024-" + strconv.Itoa(10000+i),
			Severity:    sevs[i%len(sevs)],
			AuthType:    auths[i%len(auths)],
			FromVersion: "1.0.0",
			ToVersion:   "2.0.0",
			CVSSScore:   float64(4 + i%6),
		}
	}
	return vulns
}

func BenchmarkFilterAll_NoFilter(b *testing.B) {
	vulns := makeVulns(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "", "", "", "", "")
	}
}

func BenchmarkFilterAll_ByCVE(b *testing.B) {
	vulns := makeVulns(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "CVE-2024-10050", "", "", "", "")
	}
}

func BenchmarkFilterAll_BySlug(b *testing.B) {
	vulns := makeVulns(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "", "plugin-50", "", "", "")
	}
}

func BenchmarkFilterAll_BySeverity(b *testing.B) {
	vulns := makeVulns(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "", "", "", "critical", "")
	}
}

func BenchmarkFilterAll_ByAuth(b *testing.B) {
	vulns := makeVulns(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "", "", "", "", "unauth")
	}
}

func BenchmarkFilterAll_Combined(b *testing.B) {
	vulns := makeVulns(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "", "plugin-50", "SQL", "critical", "")
	}
}

func BenchmarkFilterAll_NoMatch(b *testing.B) {
	vulns := makeVulns(5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "CVE-9999-99999", "", "", "", "")
	}
}

func BenchmarkFilterAll_Large(b *testing.B) {
	vulns := makeVulns(50000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FilterAll(vulns, "", "plugin-25", "", "high", "unauth")
	}
}

func BenchmarkGroupByPlugin_Small(b *testing.B) {
	vulns := makeVulns(100)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GroupByPlugin(vulns)
	}
}

func BenchmarkGroupByPlugin_Large(b *testing.B) {
	vulns := makeVulns(10000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GroupByPlugin(vulns)
	}
}

func BenchmarkAnyFilterSet_None(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AnyFilterSet("", "", "", "", "")
	}
}

func BenchmarkAnyFilterSet_First(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AnyFilterSet("CVE-2024-1234", "", "", "", "")
	}
}

func BenchmarkAnyFilterSet_Last(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AnyFilterSet("", "", "", "", "unauth")
	}
}
