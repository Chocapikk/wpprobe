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
	"strings"
	"testing"
)

// benchBody is a realistic ~2KB WordPress "not found" page prefix, including the
// scripts, comments and digits that normalizeBody has to strip.
var benchBody = "<!DOCTYPE html><html lang=\"en-US\"><head><meta charset=\"UTF-8\">" +
	"<title>Page not found - Example Site</title><!-- generated 1718960000 -->" +
	"<link rel=\"stylesheet\" href=\"/wp-content/themes/x/style.css?ver=6.4.2\">" +
	"<script>var wp={ajax:'/wp-admin/admin-ajax.php',n:1718960000};</script>" +
	strings.Repeat("<div class=\"widget-1234\">padding content 5678</div>", 24) +
	"</head><body class=\"error404\">Nothing found.</body></html>"

func apacheLikeCalibrator() *Calibrator {
	return &Calibrator{
		missStatuses:   map[int]struct{}{301: {}},
		missSigs:       map[responseSig]struct{}{},
		missStatusOnly: map[int]struct{}{},
		available:      true,
	}
}

func softNotFoundCalibrator() *Calibrator {
	c := &Calibrator{
		missStatuses:   map[int]struct{}{200: {}},
		missSigs:       map[responseSig]struct{}{},
		missStatusOnly: map[int]struct{}{},
		available:      true,
	}
	c.missSigs[signature(200, benchBody)] = struct{}{}
	return c
}

// Hit decided by status alone (served 200 vs 301 miss): must not touch the body.
func BenchmarkIsInstalledHitByStatus(b *testing.B) {
	c := apacheLikeCalibrator()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.IsInstalled(200, "")
	}
}

// Miss decided by status alone (301 canonical redirect): must not touch the body.
func BenchmarkIsInstalledMissByStatus(b *testing.B) {
	c := apacheLikeCalibrator()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.IsInstalled(301, "")
	}
}

// Soft-404 host: the only case that hashes a normalized body. Rare in practice.
func BenchmarkIsInstalledSoft404(b *testing.B) {
	c := softNotFoundCalibrator()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.IsInstalled(200, benchBody)
	}
}

func BenchmarkNormalizedHash(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizedHash(benchBody)
	}
}
