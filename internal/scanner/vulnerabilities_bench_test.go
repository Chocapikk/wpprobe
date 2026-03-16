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
	"strconv"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

func makeTestVulns(n, slugCount int) []wordfence.Vulnerability {
	vulns := make([]wordfence.Vulnerability, n)
	for i := 0; i < n; i++ {
		vulns[i] = wordfence.Vulnerability{
			Slug:        "plugin-" + strconv.Itoa(i%slugCount),
			CVE:         "CVE-2024-" + strconv.Itoa(10000+i),
			FromVersion: "1.0.0",
			ToVersion:   strconv.Itoa(2+i%5) + ".0.0",
		}
	}
	return vulns
}

func BenchmarkBuildVulnerabilityIndex_Small(b *testing.B) {
	vulns := makeTestVulns(100, 50)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildVulnerabilityIndex(vulns)
	}
}

func BenchmarkBuildVulnerabilityIndex_Medium(b *testing.B) {
	vulns := makeTestVulns(5000, 500)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildVulnerabilityIndex(vulns)
	}
}

func BenchmarkBuildVulnerabilityIndex_Large(b *testing.B) {
	vulns := makeTestVulns(50000, 5000)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildVulnerabilityIndex(vulns)
	}
}

func BenchmarkFindMatchingVulnerabilities_Hit(b *testing.B) {
	vulns := makeTestVulns(5000, 500)
	index := buildVulnerabilityIndex(vulns)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = findMatchingVulnerabilities("plugin", "plugin-50", "1.5.0", index)
	}
}

func BenchmarkFindMatchingVulnerabilities_Miss(b *testing.B) {
	vulns := makeTestVulns(5000, 500)
	index := buildVulnerabilityIndex(vulns)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = findMatchingVulnerabilities("plugin", "nonexistent-plugin", "1.5.0", index)
	}
}

func BenchmarkFindMatchingVulnerabilities_UnknownVersion(b *testing.B) {
	vulns := makeTestVulns(5000, 500)
	index := buildVulnerabilityIndex(vulns)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = findMatchingVulnerabilities("plugin", "plugin-50", "unknown", index)
	}
}

func BenchmarkGetOrBuildVulnerabilityIndex_Cached(b *testing.B) {
	vulns := makeTestVulns(5000, 500)
	// Prime the cache
	_ = getOrBuildVulnerabilityIndex(vulns)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getOrBuildVulnerabilityIndex(vulns)
	}
}
