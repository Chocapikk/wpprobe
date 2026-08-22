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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wphttp "github.com/Chocapikk/wpprobe/internal/http"
)

// bodySimilarity is the Sørensen-Dice coefficient used to recognise fabricated
// readme templates whose paths / generated versions vary per request.
func TestBodySimilarity(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want float64
	}{
		{"identical", "a b c", "a b c", 1},
		{"disjoint", "a b c", "x y z", 0},
		{"both empty", "", "", 1},
		{"one empty", "", "a", 0},
		{"case insensitive", "Foo BAR", "foo bar", 1},
		{"echoed path collapses", "nope at /a/readme.txt", "nope at /b/foo.php", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bodySimilarity(tt.a, tt.b); got != tt.want {
				t.Errorf("bodySimilarity(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}

	// The coefficient must land on the correct side of the suppression
	// threshold: a near-duplicate (one differing token out of many) is above it,
	// a mostly-different body is below it.
	near := bodySimilarity(
		"=== Plugin === stable tag: 1.0.0 contributors alice description here",
		"=== Plugin === stable tag: 9.9.9 contributors alice description here",
	)
	if near < missBodySimilarityThreshold {
		t.Errorf("near-duplicate similarity %.3f should be >= threshold %.2f", near, missBodySimilarityThreshold)
	}
	far := bodySimilarity(
		"=== Plugin === stable tag: 1.0.0 contributors alice",
		"completely unrelated lorem ipsum dolor sit amet consectetur",
	)
	if far >= missBodySimilarityThreshold {
		t.Errorf("unrelated similarity %.3f should be < threshold %.2f", far, missBodySimilarityThreshold)
	}
}

// Echoed request paths are the main source of otherwise-identical soft-404
// bodies differing between probes, so they are folded to a single token.
func TestSimilarityToken(t *testing.T) {
	if got := similarityToken("/no-existing-plugin/readme.txt"); got != "#path" {
		t.Errorf("path token = %q, want %q", got, "#path")
	}
	if got := similarityToken("contributors"); got != "contributors" {
		t.Errorf("plain token = %q, want unchanged", got)
	}
}

// Only 200/403/500 can be produced by BOTH a served file and a "not found"
// response, so only those ever justify hashing the body.
func TestBodyAmbiguous(t *testing.T) {
	for _, s := range []int{200, 403, 500} {
		if !bodyAmbiguous(s) {
			t.Errorf("status %d must be ambiguous", s)
		}
	}
	for _, s := range []int{301, 302, 304, 404, 410, 502} {
		if bodyAmbiguous(s) {
			t.Errorf("status %d must not be ambiguous", s)
		}
	}
}

// normalizedHash neutralises the parts of a page that legitimately vary between
// two identical requests, so a dynamic "not found" page keeps a stable
// fingerprint: inline scripts and comments are dropped, digit runs collapse, and
// whitespace runs collapse.
func TestNormalizedHashNeutralizesVolatility(t *testing.T) {
	equal := []struct {
		name string
		a, b string
	}{
		{"digit runs collapse", "error ref 1 at 170001", "error ref 9999 at 17000099999"},
		{"inline script dropped", "head<script>var n=1</script>tail", "head<script>anything else</script>tail"},
		{"html comment dropped", "head<!-- gen 1 -->tail", "head<!-- gen 99999 -->tail"},
		{"whitespace runs collapse", "a   b\n\t c", "a b c"},
	}
	for _, tt := range equal {
		t.Run(tt.name, func(t *testing.T) {
			if normalizedHash(tt.a) != normalizedHash(tt.b) {
				t.Errorf("normalizedHash should treat %q and %q as equal", tt.a, tt.b)
			}
		})
	}

	// Genuinely different content must still hash differently, or a served file
	// would be mistaken for the miss baseline.
	if normalizedHash("=== Real Plugin ===\nStable tag: 1.2.3") == normalizedHash("<html><head><title>not found</title></head>") {
		t.Error("distinct bodies must not collide after normalization")
	}
}

// The calibration slug is deliberately non-plugin-like and the three probe paths
// cover both readme casings and the plugin PHP file.
func TestNewCalibrationPaths(t *testing.T) {
	paths := newCalibrationPaths()
	if len(paths) != 3 {
		t.Fatalf("expected 3 calibration paths, got %d: %v", len(paths), paths)
	}
	slug := strings.SplitN(paths[0], "/", 2)[0]
	if !strings.HasPrefix(slug, "no-existing-plugin-") {
		t.Errorf("slug %q must carry the non-plugin-like prefix", slug)
	}
	if paths[0] != slug+"/readme.txt" ||
		paths[1] != slug+"/Readme.txt" ||
		paths[2] != slug+"/"+slug+".php" {
		t.Errorf("unexpected calibration path shape: %v", paths)
	}
}

// A constructed calibrator must treat a body that is similar enough to a
// calibrated miss template as a miss (fabricated readme whose version/path
// changes per request), while a clearly different served body stays a hit.
func TestCalibratorSimilarityMiss(t *testing.T) {
	template := "=== Fake Plugin === stable tag: 1.0.0 contributors waf served for any slug"
	c := &Calibrator{
		missStatuses: map[int]struct{}{200: {}},
		missSigs:     map[responseSig]struct{}{},
		missBodies:   map[int][]string{200: {template}},
		available:    true,
	}

	fabricatedVariant := "=== Fake Plugin === stable tag: 9.9.9 contributors waf served for any slug"
	if c.IsInstalled(200, fabricatedVariant) {
		t.Error("a per-request variant of the fabricated template must be a miss")
	}
	realPlugin := "wordpress plugin bootstrap file totally unrelated content here"
	if !c.IsInstalled(200, realPlugin) {
		t.Error("a genuinely different served body must be a hit")
	}
}

// End-to-end calibration against a host that fabricates plugin content: a 200
// carrying "Stable tag:" for the random, certainly-absent slug flags the host,
// and responses matching that template are treated as misses.
func TestNewCalibratorFabricatedContent(t *testing.T) {
	fabricated := "=== Fake Plugin ===\nStable tag: 9.9.9\nContributors: waf\n" +
		"This fabricated readme is served for any plugin slug by the firewall.\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fabricated))
	}))
	defer srv.Close()

	client := wphttp.NewHTTPClient(5*time.Second, nil, "", 0, 0)
	c := NewCalibrator(context.Background(), client, srv.URL)

	if !c.available {
		t.Fatal("calibration should be available")
	}
	if !c.FabricatesContent() {
		t.Fatal("a 200 + \"Stable tag:\" response for an absent slug must flag the host")
	}
	if c.IsInstalled(http.StatusOK, fabricated) {
		t.Error("a response matching the fabricated template must be a miss")
	}
}

// Regression for the BitFire case (PR #31): the host fabricates a readme for
// ANY path that does not exist, including <real-plugin>/Readme.txt, and varies
// the version on every request. Calibration must still leave real plugins,
// whose readme.txt is genuinely served, detected. An earlier revision confirmed
// each detected plugin by re-probing Readme.txt, which the host fabricates for
// exactly the same reason it fabricated during calibration, so every real
// plugin was discarded.
func TestCalibratorKeepsRealPluginsOnFabricatingHost(t *testing.T) {
	realReadme := "=== Contact Form 7 ===\n" +
		"Contributors: takayukister\nTags: contact, form, feedback, email, ajax\n" +
		"Requires at least: 6.0\nTested up to: 6.4\nStable tag: 5.8.4\n" +
		"License: GPLv2 or later\n== Description ==\n" +
		"Just another contact form plugin. Simple but flexible."

	// Only this exact path exists; every other path gets the template, with a
	// version that changes per request, as BitFire does.
	const existing = "/wp-content/plugins/contact-form-7/readme.txt"
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == existing {
			_, _ = w.Write([]byte(realReadme))
			return
		}
		requests++
		_, _ = fmt.Fprintf(w, "=== Plugin Name ===\n"+
			"Tags: security, performance, caching, headers, monitoring\n"+
			"Requires at least: 5.2\nTested up to: 7.0\nStable tag: %d.%d.%d\n"+
			"Requires PHP: 7.4\nLicense: GPLv2 or later\n"+
			"Lightweight site hardening and performance tweaks.\n",
			requests%9+1, requests%7+1, requests%5+1)
	}))
	defer srv.Close()

	client := wphttp.NewHTTPClient(5*time.Second, nil, "", 0, 0)
	c := NewCalibrator(context.Background(), client, srv.URL)

	if !c.FabricatesContent() {
		t.Fatal("the fabricating host must be flagged during calibration")
	}
	// The per-request version must not defeat the baseline: distinct versions
	// normalize to one signature, so a single body is stored.
	if got := len(c.missBodies[200]); got != 1 {
		t.Errorf("expected the varying template to collapse to 1 stored body, got %d", got)
	}
	if !c.IsInstalled(http.StatusOK, realReadme) {
		t.Error("a real plugin readme must stay detected on a fabricating host")
	}
	if c.IsInstalled(http.StatusOK, "=== Plugin Name ===\n"+
		"Tags: security, performance, caching, headers, monitoring\n"+
		"Requires at least: 5.2\nTested up to: 7.0\nStable tag: 4.2.1\n"+
		"Requires PHP: 7.4\nLicense: GPLv2 or later\n"+
		"Lightweight site hardening and performance tweaks.\n") {
		t.Error("a fresh variant of the fabricated template must be a miss")
	}
}

// The fabricated-content suppression threshold is a heuristic, and its whole safety rests
// on the margin between "two genuinely different plugin readmes" and "the same
// fabricated template served for a different slug/version". This test brackets
// missBodySimilarityThreshold so the margin cannot be silently broken:
//
//   - Lowering it (to "catch more") until a real plugin's readme scores above it
//     would suppress real plugins as fabricated (false negatives). Real, distinct
//     readmes must stay BELOW the threshold.
//   - Raising it until a per-request template variant scores below it would let
//     the fabricated response through (false positives). A near-duplicate
//     template must stay AT or ABOVE the threshold.
//
// Measured values at time of writing: two real readmes ~0.36, real vs fabricated
// template ~0.42-0.44, near-duplicate template ~0.93. Against a live BitFire
// host the margin is wider still: real readmes score 0.19-0.26 against the
// served template, while two of its per-request variants score 0.996.
func TestFabricatedSuppressionMargin(t *testing.T) {
	realA := "=== Contact Form 7 ===\n" +
		"Contributors: takayukister\n" +
		"Tags: contact, form, feedback, email, ajax\n" +
		"Requires at least: 6.0\nTested up to: 6.4\nStable tag: 5.8.4\n" +
		"License: GPLv2 or later\n== Description ==\n" +
		"Just another contact form plugin. Simple but flexible. Contact Form 7 " +
		"can manage multiple contact forms, plus you can customize the form and " +
		"the mail contents flexibly with simple markup."
	realB := "=== Yoast SEO ===\n" +
		"Contributors: yoast, joostdevalk, tacoverdo\n" +
		"Tags: SEO, XML sitemap, content analysis, readability, schema\n" +
		"Requires at least: 6.2\nTested up to: 6.4\nStable tag: 21.7\n" +
		"License: GPLv3\n== Description ==\n" +
		"Improve your WordPress SEO: write better content and have a fully " +
		"optimized WordPress site using the Yoast SEO plugin."
	fabricated := "=== Plugin ===\n" +
		"Contributors: admin\nTags: wordpress, plugin\n" +
		"Requires at least: 5.0\nTested up to: 6.4\nStable tag: 1.0.0\n" +
		"License: GPLv2 or later\n== Description ==\n" +
		"This plugin is installed and active on this site."
	// Same template, only the per-request slug/version differs.
	fabricatedVariant := "=== Plugin ===\n" +
		"Contributors: admin\nTags: wordpress, plugin\n" +
		"Requires at least: 5.0\nTested up to: 6.4\nStable tag: 9.9.9\n" +
		"License: GPLv2 or later\n== Description ==\n" +
		"This plugin is installed and active on this site."

	// Real plugins must NOT be suppressed: they stay below the threshold.
	if s := bodySimilarity(realA, realB); s >= missBodySimilarityThreshold {
		t.Errorf("two genuine readmes scored %.3f >= threshold %.2f: lowering the "+
			"threshold this far would suppress real plugins", s, missBodySimilarityThreshold)
	}
	if s := bodySimilarity(realA, fabricated); s >= missBodySimilarityThreshold {
		t.Errorf("a real readme vs the fabricated template scored %.3f >= threshold %.2f: "+
			"real plugins on a fabricating host would be hidden", s, missBodySimilarityThreshold)
	}

	// Fabricated template variants MUST be suppressed: they stay at/above threshold.
	if s := bodySimilarity(fabricated, fabricatedVariant); s < missBodySimilarityThreshold {
		t.Errorf("a per-request variant of the fabricated template scored %.3f < threshold "+
			"%.2f: raising the threshold this high would let the fabricated readme through", s, missBodySimilarityThreshold)
	}
}
