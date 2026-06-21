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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wphttp "github.com/Chocapikk/wpprobe/internal/http"
)

// IsInstalled must flag any response that differs from the calibrated miss
// baseline as a hit, covering the nginx shape (missing .php -> 404, missing
// readme -> 301) and the responses a real, served or hardened file produces.
func TestCalibratorIsInstalled(t *testing.T) {
	c := &Calibrator{
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

// A 404 page that echoes the requested path yields different bodies per slug;
// the calibrator must downgrade that status to status-only matching so it does
// not mistake every miss for a hit.
func TestNewCalibratorEchoingNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "wpprobe-calib") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Not found: " + r.URL.Path)) // echoes the path
			return
		}
		_, _ = w.Write([]byte("real served content"))
	}))
	defer srv.Close()

	client := wphttp.NewHTTPClient(5*time.Second, nil, "", 0, 0)
	c := NewCalibrator(context.Background(), client, srv.URL)

	if _, ok := c.missStatusOnly[http.StatusNotFound]; !ok {
		t.Fatal("an echoing 404 should be tracked as a status-only miss")
	}
	if c.IsInstalled(404, "Not found: /anything/else") {
		t.Error("any 404 must be a miss once the status is echo-detected")
	}
	if !c.IsInstalled(200, "real served content") {
		t.Error("a served 200 must be installed")
	}
}
