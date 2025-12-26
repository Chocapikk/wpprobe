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
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func TestDetectPlugins(t *testing.T) {
	tests := []struct {
		name              string
		detectedEndpoints []string
		pluginEndpoints   map[string][]string
		want              PluginDetectionResult
	}{
		{
			name: "Detect single plugin",
			detectedEndpoints: []string{
				"/endpoint1", "/endpoint2",
			},
			pluginEndpoints: map[string][]string{
				"plugin1": {"/endpoint1", "/endpoint2", "/endpoint3"},
			},
			want: PluginDetectionResult{
				Plugins: map[string]*PluginData{
					"plugin1": {
						Score:      2,
						Confidence: 66.67,
						Ambiguous:  false,
						Matches:    []string{},
					},
				},
				Detected: []string{"plugin1"},
			},
		},
		{
			name: "Ambiguous plugins",
			detectedEndpoints: []string{
				"/shared-endpoint",
			},
			pluginEndpoints: map[string][]string{
				"plugin1": {"/shared-endpoint"},
				"plugin2": {"/shared-endpoint"},
			},
			want: PluginDetectionResult{
				Plugins: map[string]*PluginData{
					"plugin1": {
						Score:      1,
						Confidence: 100.00,
						Ambiguous:  true,
						Matches:    []string{"plugin1", "plugin2"},
					},
					"plugin2": {
						Score:      1,
						Confidence: 100.00,
						Ambiguous:  true,
						Matches:    []string{"plugin1", "plugin2"},
					},
				},
				Detected: []string{"plugin1", "plugin2"},
			},
		},
		{
			name:              "No plugins detected",
			detectedEndpoints: []string{"/unknown-endpoint"},
			pluginEndpoints: map[string][]string{
				"plugin1": {"/endpoint1", "/endpoint2"},
			},
			want: PluginDetectionResult{
				Plugins:  map[string]*PluginData{},
				Detected: []string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectPlugins(tt.detectedEndpoints, tt.pluginEndpoints)
			gotVal := toCompare(got)
			wantVal := toCompare(tt.want)
			if !compareDetections(gotVal, wantVal) {
				t.Errorf("DetectPlugins() = %+v, want %+v", gotVal, wantVal)
			}
		})
	}
}

type compareValue struct {
	Plugins  map[string]comparePlugin
	Detected []string
}

type comparePlugin struct {
	Score      int
	Confidence float64
	Ambiguous  bool
	Matches    []string
}

func toCompare(r PluginDetectionResult) compareValue {
	cv := compareValue{
		Plugins:  make(map[string]comparePlugin),
		Detected: append([]string(nil), r.Detected...),
	}
	sort.Strings(cv.Detected)
	for k, v := range r.Plugins {
		if v != nil {
			cv.Plugins[k] = comparePlugin{
				Score:      v.Score,
				Confidence: v.Confidence,
				Ambiguous:  v.Ambiguous,
				Matches:    append([]string(nil), v.Matches...),
			}
		}
	}
	return cv
}

func compareDetections(got, want compareValue) bool {
	if len(got.Plugins) != len(want.Plugins) {
		return false
	}
	sort.Strings(got.Detected)
	sort.Strings(want.Detected)
	if !reflect.DeepEqual(got.Detected, want.Detected) {
		return false
	}
	for k, v := range want.Plugins {
		gv, ok := got.Plugins[k]
		if !ok {
			return false
		}
		if gv.Score != v.Score {
			return false
		}
		if fmt.Sprintf("%.2f", gv.Confidence) !=
			fmt.Sprintf("%.2f", v.Confidence) {
			return false
		}
		if gv.Ambiguous != v.Ambiguous {
			return false
		}
		sort.Strings(gv.Matches)
		sort.Strings(v.Matches)
		if !reflect.DeepEqual(gv.Matches, v.Matches) {
			return false
		}
	}
	return true
}

