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

package version

import (
	"strconv"
	"sync"
	"testing"
)

func BenchmarkIsVersionVulnerable_Hit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsVersionVulnerable("1.5.0", "1.0.0", "2.0.0")
	}
}

func BenchmarkIsVersionVulnerable_Miss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsVersionVulnerable("3.0.0", "1.0.0", "2.0.0")
	}
}

func BenchmarkIsVersionVulnerable_InvalidVersion(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsVersionVulnerable("not-a-version", "1.0.0", "2.0.0")
	}
}

func BenchmarkIsVersionVulnerable_EmptyInputs(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsVersionVulnerable("", "1.0.0", "2.0.0")
	}
}

func BenchmarkParseSemverCached_CacheHit(b *testing.B) {
	// Prime the cache
	parseSemverCached("5.0.0")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseSemverCached("5.0.0")
	}
}

func BenchmarkParseSemverCached_CacheMiss(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clear cache each iteration to force misses
		semverCache = sync.Map{}
		parseSemverCached("6." + strconv.Itoa(i) + ".0")
	}
}

func BenchmarkIsVersionVulnerable_ManyVersions(b *testing.B) {
	// Simulate scanning one plugin version against many vuln ranges
	versions := make([][2]string, 500)
	for i := 0; i < 500; i++ {
		versions[i] = [2]string{
			strconv.Itoa(i) + ".0.0",
			strconv.Itoa(i+1) + ".0.0",
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, vr := range versions {
			_ = IsVersionVulnerable("250.0.0", vr[0], vr[1])
		}
	}
}

func BenchmarkIsVersionVulnerable_RealisticWorkload(b *testing.B) {
	// Realistic: same version strings appear repeatedly (cache benefits)
	type check struct {
		ver, from, to string
	}
	checks := []check{
		{"3.1.2", "1.0.0", "3.2.0"},
		{"5.4.1", "5.0.0", "5.5.0"},
		{"2.0.0", "1.0.0", "1.9.9"},
		{"3.1.2", "3.0.0", "4.0.0"},
		{"5.4.1", "5.4.0", "5.4.2"},
		{"1.0.0", "1.0.0", "2.0.0"},
		{"3.1.2", "1.0.0", "3.2.0"}, // repeated
		{"5.4.1", "5.0.0", "5.5.0"}, // repeated
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range checks {
			_ = IsVersionVulnerable(c.ver, c.from, c.to)
		}
	}
}
