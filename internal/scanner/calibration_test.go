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
	"sync/atomic"
	"testing"
	"time"

	wphttp "github.com/Chocapikk/wpprobe/internal/http"
)

// IsInstalled must flag any response that differs from the calibrated miss
// baseline as a hit, covering the nginx shape (missing .php -> 404, missing
// readme -> 301) and the responses a real, served or hardened file produces.
func TestCalibratorIsInstalled(t *testing.T) {
	c := &Calibrator{
		missStatuses: map[int]struct{}{404: {}, 301: {}},
		missSigs: map[responseSig]struct{}{
			signature(404, "nginx not found"): {},
			signature(301, ""):                {},
		},
		missStatusOnly: map[int]struct{}{},
		available:      true,
	}
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"executed php, empty 200", 200, "", true},
		{"served readme, 200", 200, "=== My Plugin ===", true},
		{"hardened, 403", 403, "<html>403 forbidden</html>", true},
		{"missing php, 404", 404, "nginx not found", false},
		{"missing readme, 301", 301, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.IsInstalled(tt.status, tt.body); got != tt.want {
				t.Errorf("IsInstalled(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}

// When calibration could not run, fall back to "served (200) or hardened (403)".
func TestCalibratorUnavailableFallback(t *testing.T) {
	c := &Calibrator{available: false}
	if !c.IsInstalled(200, "") {
		t.Error("200 should be considered installed in fallback mode")
	}
	if !c.IsInstalled(403, "") {
		t.Error("403 should be considered installed in fallback mode")
	}
	if c.IsInstalled(404, "x") {
		t.Error("404 should not be considered installed in fallback mode")
	}
}

// NewCalibrator against an Apache-style host: every missing path is a 301 to
// "<path>/". A served file (200) and a hardened file (403) must both be hits.
func TestNewCalibratorApacheStyle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	client := wphttp.NewHTTPClient(5*time.Second, nil, "", 0, 0)
	c := NewCalibrator(context.Background(), client, srv.URL)

	if !c.available {
		t.Fatal("calibration should be available")
	}
	if c.IsInstalled(301, "") {
		t.Error("a 301 (the miss shape) must not be installed")
	}
	if !c.IsInstalled(200, "") {
		t.Error("a served/executed 200 must be installed")
	}
	if !c.IsInstalled(403, "denied") {
		t.Error("a hardened 403 must be installed")
	}
}

// A soft-404 host (200 for everything) whose page carries a per-request token
// (timestamp, cache buster) must not produce false positives: after body
// normalization the changing digits collapse, so a non-installed plugin still
// matches the calibrated miss, while a real served file is still a hit.
func TestNewCalibratorDynamicNotFound(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "this-is-a-real-plugin") {
			_, _ = w.Write([]byte("=== Real Plugin ===\nStable tag: 1.2.3\nContributors: someone\n"))
			return
		}
		i := atomic.AddInt64(&n, 1)
		_, _ = fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>Page not found</title></head><body>error ref %d at 170000%d</body></html>", i, i)
	}))
	defer srv.Close()

	client := wphttp.NewHTTPClient(5*time.Second, nil, "", 0, 0)
	c := NewCalibrator(context.Background(), client, srv.URL)

	if _, ok := c.missStatusOnly[http.StatusOK]; ok {
		t.Fatal("normalized dynamic page should be stable, not status-only")
	}
	missWithOtherToken := "<!DOCTYPE html><html><head><title>Page not found</title></head><body>error ref 9999 at 17000099999</body></html>"
	if c.IsInstalled(http.StatusOK, missWithOtherToken) {
		t.Error("a dynamic soft-404 page must be a miss, not a false positive")
	}
	if !c.IsInstalled(http.StatusOK, "=== Real Plugin ===\nStable tag: 1.2.3\nContributors: someone\n") {
		t.Error("a served plugin file must be a hit")
	}
}

// A redirect must never count as "installed", even when the calibrated miss
// baseline uses a different status (e.g. 404). This covers hosts where a WAF
// or reverse proxy returns 301/302 for specific plugin slugs while calibration
// saw only 404 (issue #27, corvuspay false positive).
func TestCalibratorRedirectNeverInstalled(t *testing.T) {
	c := &Calibrator{
		missStatuses:   map[int]struct{}{404: {}},
		missSigs:       map[responseSig]struct{}{signature(404, "not found"): {}},
		missStatusOnly: map[int]struct{}{},
		available:      true,
	}
	for _, status := range []int{301, 302, 303, 307, 308} {
		if c.IsInstalled(status, "") {
			t.Errorf("redirect %d must never be considered installed", status)
		}
	}
	if !c.IsInstalled(200, "plugin content") {
		t.Error("200 must still be installed")
	}
	if !c.IsInstalled(403, "denied") {
		t.Error("403 must still be installed")
	}
}

// Redirect must be rejected even when calibration failed (fallback mode).
func TestCalibratorRedirectFallback(t *testing.T) {
	c := &Calibrator{available: false}
	if c.IsInstalled(301, "") {
		t.Error("301 must not be installed in fallback mode")
	}
	if c.IsInstalled(302, "") {
		t.Error("302 must not be installed in fallback mode")
	}
}

// A soft-404 host (200 for everything) that echoes the requested path makes
// every probe body different, even after normalization. The ambiguous 200
// status must be downgraded to status-only so detection stays conservative (a
// miss) instead of flagging every probe as a hit.
func TestNewCalibratorEchoingNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>Nothing here at " + r.URL.Path + "</body></html>"))
	}))
	defer srv.Close()

	client := wphttp.NewHTTPClient(5*time.Second, nil, "", 0, 0)
	c := NewCalibrator(context.Background(), client, srv.URL)

	if _, ok := c.missStatusOnly[http.StatusOK]; !ok {
		t.Fatal("an echoing soft-404 (200) should be tracked as a status-only miss")
	}
	if c.IsInstalled(http.StatusOK, "<html><body>Nothing here at /whatever</body></html>") {
		t.Error("an echoing soft-404 200 must be treated as a miss")
	}
}
