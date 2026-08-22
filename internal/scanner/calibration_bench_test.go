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
		missStatuses: map[int]struct{}{301: {}},
		missSigs:     map[responseSig]struct{}{},
		available:    true,
	}
}

func softNotFoundCalibrator() *Calibrator {
	c := &Calibrator{
		missStatuses: map[int]struct{}{200: {}},
		missSigs:     map[responseSig]struct{}{},
		available:    true,
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

// Soft-404 host whose body is byte-stable: the exact signature settles it, so
// this measures the hash alone and never reaches the similarity pass below.
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

// fabricatedTemplate mimics what a host like BitFire serves for a slug that
// cannot exist: a plausible readme whose version changes on every request, so
// the exact signature never matches and only the similarity pass can reject it.
const fabricatedTemplate = "=== Plugin Name ===\n" +
	"Tags: security, performance, caching, headers, monitoring\n" +
	"Requires at least: 5.2\nTested up to: 7.0\nStable tag: 6.4.6\n" +
	"Requires PHP: 7.4\nLicense: GPLv2 or later\n" +
	"License URI: https://www.gnu.org/licenses/gpl-2.0.html\n\n" +
	"Lightweight site hardening and performance tweaks, adds safe headers, " +
	"page cache, uptime pings, and simple health checks.\n\n== Description ==\n\n" +
	"Plugin Name adds a small set of safe defaults for typical WordPress sites. " +
	"It focuses on three areas, basic security headers, lightweight page caching, " +
	"and simple site health checks. No complicated setup, sensible defaults work " +
	"out of the box.\n\n== Features ==\n\n" +
	"- Security headers, Content Security Policy scaffold, Referrer Policy.\n" +
	"- Cache helper, static file cache for visitors.\n" +
	"- Uptime endpoint, /wp-json/plugin-name/v1/ping returns a fast OK.\n" +
	"- Opt in logs stored in wp-content/uploads/plugin-name/ for quick review.\n"

// realReadme is a genuine plugin readme: it must survive the similarity pass on
// a fabricating host, which is the expensive case since no stored body matches
// and every one of them is compared.
const realReadme = "=== Contact Form 7 ===\n" +
	"Contributors: rocklobsterinc, takayukister\n" +
	"Donate link: https://contactform7.com/donate/\n" +
	"Tags: contact form, contact us, email, feedback, message\n" +
	"Tested up to: 7.1\nRequires at least: 6.7\nRequires PHP: 7.4\n" +
	"Stable tag: 6.1.7\nLicense: GPLv2 or later\n" +
	"License URI: https://www.gnu.org/licenses/gpl-2.0.html\n\n" +
	"Just another contact form plugin. Simple but flexible.\n\n== Description ==\n\n" +
	"Contact Form 7 can manage multiple contact forms, plus you can customize the " +
	"form and the mail contents flexibly with simple markup. The form supports " +
	"Ajax-powered submitting, CAPTCHA, Akismet spam filtering and so on.\n\n" +
	"== Docs and support ==\n\nYou can find docs, FAQ and more detailed " +
	"information about Contact Form 7 on contactform7.com. If you were unable to " +
	"find the answer to your question on the FAQ or in the documentation, check " +
	"the support forum on WordPress.org.\n"

// fabricatingHostCalibrator fills missBodies to maxMissBodiesPerStatus so the
// similarity pass runs its full worst case, as it would on a host that answers
// absent paths with several distinct templates.
func fabricatingHostCalibrator() *Calibrator {
	c := &Calibrator{
		missStatuses:      map[int]struct{}{200: {}},
		missSigs:          map[responseSig]struct{}{},
		missBodies:        map[int][]string{},
		fabricatesContent: true,
		available:         true,
	}
	for i := 0; i < maxMissBodiesPerStatus; i++ {
		c.recordMissBody(200, strings.ReplaceAll(
			fabricatedTemplate, "Plugin Name", "Plugin Name "+string(rune('A'+i))))
	}
	return c
}

// The similarity pass itself, run once per ambiguous probe that the exact
// signature did not settle.
func BenchmarkBodySimilarity(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bodySimilarity(realReadme, fabricatedTemplate)
	}
}

// Fabricating host, absent plugin: the response is a fresh variant of a stored
// template, so it is rejected by the first comparison.
func BenchmarkIsInstalledFabricatedMiss(b *testing.B) {
	c := fabricatingHostCalibrator()
	variant := strings.Replace(fabricatedTemplate, "6.4.6", "2.9.1", 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.IsInstalled(200, variant)
	}
}

// Fabricating host, real plugin: nothing matches, so every stored body is
// compared. This is the worst case a brute-force run pays per detected plugin,
// and what maxMissBodiesPerStatus bounds.
func BenchmarkIsInstalledRealPluginOnFabricatingHost(b *testing.B) {
	c := fabricatingHostCalibrator()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.IsInstalled(200, realReadme)
	}
}
