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

	"github.com/Chocapikk/wpprobe/internal/file"
)

func TestScannedPluginsJSON_NoDoubleEscapedBackslashes(t *testing.T) {
	data, err := file.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		t.Fatalf("failed to load scanned_plugins.json: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		if strings.Contains(line, `\\\\`) {
			t.Errorf("line %d contains over-escaped backslashes (\\\\\\\\): %s",
				i+1, line[:min(len(line), 120)])
		}
	}
}

func TestScannedPluginsJSON_RoutesLoadAndMatchCorrectly(t *testing.T) {
	data, err := file.GetEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		t.Fatalf("failed to load scanned_plugins.json: %v", err)
	}

	endpoints, err := LoadPluginEndpointsFromData(data)
	if err != nil {
		t.Fatalf("LoadPluginEndpointsFromData() error: %v", err)
	}

	if len(endpoints) < 5000 {
		t.Fatalf("expected at least 5000 plugins, got %d", len(endpoints))
	}

	for slug, routes := range endpoints {
		for _, route := range routes {
			if strings.Contains(route, `\\`) {
				t.Errorf("plugin %q has route with double backslash in decoded string: %s",
					slug, route)
			}
		}
	}
}

func TestDetectPlugins_BackslashEscaping(t *testing.T) {
	// WordPress REST API returns routes with single backslashes in regex patterns.
	// The scanned_plugins.json must match these exactly.
	wpEndpoints := []string{
		"/myplugin/v1",
		`/myplugin/v1/item/(?P<id>\d+)`,
		`/myplugin/v1/search/(?P<query>\w+)`,
	}

	tests := []struct {
		name           string
		pluginRoutes   map[string][]string
		wantConfidence float64
	}{
		{
			name: "Correct single backslash matches WordPress",
			pluginRoutes: map[string][]string{
				"myplugin": {
					"/myplugin/v1",
					`/myplugin/v1/item/(?P<id>\d+)`,
					`/myplugin/v1/search/(?P<query>\w+)`,
				},
			},
			wantConfidence: 100.00,
		},
		{
			name: "Double backslash fails to match WordPress",
			pluginRoutes: map[string][]string{
				"myplugin": {
					"/myplugin/v1",
					`/myplugin/v1/item/(?P<id>\\d+)`,
					`/myplugin/v1/search/(?P<query>\\w+)`,
				},
			},
			wantConfidence: 33.33,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectPlugins(wpEndpoints, tt.pluginRoutes)
			plugin, ok := result.Plugins["myplugin"]
			if !ok {
				t.Fatal("myplugin not detected")
			}
			if plugin.Confidence != tt.wantConfidence {
				t.Errorf("confidence = %.2f, want %.2f", plugin.Confidence, tt.wantConfidence)
			}
		})
	}
}

func TestLoadPluginEndpointsFromData_BackslashPreservation(t *testing.T) {
	// JSON \\d decodes to \d in the Go string (correct for regex matching)
	ndjson := []byte(`{"testplugin": ["/test/v1", "/test/v1/(?P<id>\\d+)"]}`)

	endpoints, err := LoadPluginEndpointsFromData(ndjson)
	if err != nil {
		t.Fatalf("LoadPluginEndpointsFromData() error: %v", err)
	}

	routes := endpoints["testplugin"]
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}

	want := `/test/v1/(?P<id>\d+)`
	if routes[1] != want {
		t.Errorf("route = %q, want %q", routes[1], want)
	}

	if strings.Contains(routes[1], `\\`) {
		t.Errorf("decoded route should not contain double backslash: %q", routes[1])
	}
}
