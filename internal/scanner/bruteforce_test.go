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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	wphttp "github.com/Chocapikk/wpprobe/internal/http"
)

func containsSlug(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// candidateFiles must use the curated fingerprint when present, and otherwise
// reconstruct a generic set from the slug, so a plain slug list keeps working.
func TestCandidateFiles(t *testing.T) {
	fingerprints := map[string][]string{
		"woocommerce": {"woocommerce.php", "readme.txt"},
	}

	if got := candidateFiles("woocommerce", fingerprints); !slicesEqual(got, []string{"woocommerce.php", "readme.txt"}) {
		t.Errorf("curated slug: got %v", got)
	}

	want := []string{"some-obscure-plugin.php", "readme.txt", "index.php"}
	if got := candidateFiles("some-obscure-plugin", fingerprints); !slicesEqual(got, want) {
		t.Errorf("generic reconstruction: got %v, want %v", got, want)
	}

	if got := candidateFiles("anything", nil); !slicesEqual(got, []string{"anything.php", "readme.txt", "index.php"}) {
		t.Errorf("nil fingerprints: got %v", got)
	}
}

// wafServer simulates a host that answers a missing path with 404 (so the
// calibration baseline is {404}) but forbids (403) any path whose slug is in
// blocked, regardless of whether the plugin is installed, and serves the one
// installed plugin with a 200 plus a versioned readme.
func wafServer(installed string, blocked []string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if installed != "" && strings.Contains(p, installed) {
			if strings.HasSuffix(p, "readme.txt") {
				_, _ = w.Write([]byte("=== Installed ===\nStable tag: 1.2.3\n"))
				return
			}
			w.WriteHeader(http.StatusOK) // executed php, empty 200
			return
		}
		for _, b := range blocked {
			if strings.Contains(p, b) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// A WAF that returns 403 for more slugs than the threshold must not turn those
// slugs into findings: they are not installed, the WAF just filters the path
// (issue #27). The one genuinely served plugin must still be detected.
func TestBruteforcePluginsWAFForbiddenSuppressed(t *testing.T) {
	installed := "contact-form-7"
	blocked := []string{
		"force-reinstall", "health-check", "force-admin-color-scheme",
		"filter-admin-published-default", "fullestop-lock-down-admin",
		"wp-file-manager", "duplicator",
	} // 7 > forbiddenWAFThreshold (5)

	srv := wafServer(installed, blocked)
	defer srv.Close()

	detected, _ := BruteforcePlugins(BruteforceRequest{
		Target:  srv.URL,
		Plugins: append([]string{installed}, blocked...),
		Threads: 4,
		HTTP:    wphttp.Config{},
	})

	if !containsSlug(detected, installed) {
		t.Errorf("served plugin %q must be detected, got %v", installed, detected)
	}
	for _, b := range blocked {
		if containsSlug(detected, b) {
			t.Errorf("WAF-forbidden slug %q must be suppressed, got %v", b, detected)
		}
	}
}

// A WAF/reverse proxy that returns 301 for specific plugin slugs while the
// calibration baseline is 404 must not produce false positives. This is the
// exact scenario from issue #27 (corvuspay-woocommerce-integration FP).
func TestBruteforcePluginsRedirectNotDetected(t *testing.T) {
	installed := "contact-form-7"
	redirected := []string{"corvuspay-woocommerce-integration", "some-other-plugin"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.Contains(p, installed) {
			if strings.HasSuffix(p, "readme.txt") {
				_, _ = w.Write([]byte("=== CF7 ===\nStable tag: 5.9\n"))
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		for _, slug := range redirected {
			if strings.Contains(p, slug) {
				http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	all := append([]string{installed}, redirected...)
	detected, _ := BruteforcePlugins(BruteforceRequest{
		Target:  srv.URL,
		Plugins: all,
		Threads: 4,
		HTTP:    wphttp.Config{},
	})

	if !containsSlug(detected, installed) {
		t.Errorf("served plugin %q must be detected, got %v", installed, detected)
	}
	for _, slug := range redirected {
		if containsSlug(detected, slug) {
			t.Errorf("redirected slug %q must not be detected, got %v", slug, detected)
		}
	}
}

// A handful of 403s (at or below the threshold) are plausibly real plugins
// hardened with their own .htaccess and must still be reported, so the WAF
// guard does not regress the hardened-plugin detection v0.12 shipped (issue #27).
func TestBruteforcePluginsFewForbiddenKept(t *testing.T) {
	installed := "akismet"
	hardened := []string{"hello-dolly", "jetpack"} // 2 <= forbiddenWAFThreshold

	srv := wafServer(installed, hardened)
	defer srv.Close()

	detected, _ := BruteforcePlugins(BruteforceRequest{
		Target:  srv.URL,
		Plugins: append([]string{installed}, hardened...),
		Threads: 4,
		HTTP:    wphttp.Config{},
	})

	for _, want := range append([]string{installed}, hardened...) {
		if !containsSlug(detected, want) {
			t.Errorf("plugin %q (served or few-hardened) must be detected, got %v", want, detected)
		}
	}
}
