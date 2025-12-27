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
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Chocapikk/wpprobe/internal/http"
)

func TestCheckLatestVersion(t *testing.T) {
	mockServer := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		tags := []struct {
			Name string `json:"name"`
		}{
			{Name: "v1.0.0"},
			{Name: "v1.2.0"},
			{Name: "v1.1.0"},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tags); err != nil {
			t.Errorf("Failed to encode JSON: %v", err)
		}
	}))
	defer mockServer.Close()

	originalTagsURL := tagsURL
	tagsURL = mockServer.URL
	defer func() { tagsURL = originalTagsURL }()

	tests := []struct {
		name           string
		currentVersion string
		want           string
		wantIsLatest   bool
	}{
		{"Current is latest", "v1.2.0", "1.2.0", true},
		{"Current is outdated", "v1.0.0", "1.2.0", false},
		{"Invalid current version", "invalid", "1.2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, isLatest := CheckLatestVersion(tt.currentVersion)
			if got != tt.want {
				t.Errorf("CheckLatestVersion() got = %v, want %v", got, tt.want)
			}
			if isLatest != tt.wantIsLatest {
				t.Errorf("CheckLatestVersion() isLatest = %v, want %v", isLatest, tt.wantIsLatest)
			}
		})
	}
}

func TestGetPluginVersion(t *testing.T) {
	mockServer := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		var err error
		switch r.URL.Path {
		case "/wp-content/plugins/test-plugin/readme.txt":
			_, err = fmt.Fprintln(w, "Stable tag: 1.0.0")
		default:
			nethttp.NotFound(w, r)
		}
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	tests := []struct {
		name     string
		target   string
		plugin   string
		expected string
	}{
		{
			name:     "Plugin version from readme",
			target:   mockServer.URL,
			plugin:   "test-plugin",
			expected: "1.0.0",
		},
		{
			name:     "Unknown plugin",
			target:   mockServer.URL,
			plugin:   "nonexistent",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPluginVersion(tt.target, tt.plugin, nil, "", 0)
			if got != tt.expected {
				t.Errorf("GetPluginVersion() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func Test_fetchVersionFromReadme(t *testing.T) {
	mockServer := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if _, err := w.Write([]byte("Stable tag: 3.4.1")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	client := http.NewHTTPClient(5*time.Second, nil, "", 0, -1)
	version := fetchVersionFromReadme(client, mockServer.URL, "sample")
	if version != "3.4.1" {
		t.Errorf("fetchVersionFromReadme() = %v, want %v", version, "3.4.1")
	}
}

func TestIsVersionVulnerable(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		from       string
		to         string
		wantResult bool
	}{
		{"Within range", "1.5.0", "1.0.0", "2.0.0", true},
		{"Below range", "0.9.9", "1.0.0", "2.0.0", false},
		{"Above range", "2.1.0", "1.0.0", "2.0.0", false},
		{"Exact lower bound", "1.0.0", "1.0.0", "2.0.0", true},
		{"Exact upper bound", "2.0.0", "1.0.0", "2.0.0", true},
		{"Invalid version", "invalid", "1.0.0", "2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsVersionVulnerable(tt.version, tt.from, tt.to)
			if got != tt.wantResult {
				t.Errorf("IsVersionVulnerable() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}
