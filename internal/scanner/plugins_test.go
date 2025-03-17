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

func TestLoadPluginEndpointsFromData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "Valid JSON data",
			data: []byte(`{"plugin1": ["/endpoint1", "/endpoint2"], "plugin2": ["/endpoint3"]}`),
			want: map[string][]string{
				"plugin1": {"/endpoint1", "/endpoint2"},
				"plugin2": {"/endpoint3"},
			},
		},
		{
			name: "Invalid JSON data",
			data: []byte(`{"plugin1": ["/endpoint1", "/endpoint2",]}`),
			want: map[string][]string{},
		},
		{
			name: "Empty data",
			data: []byte(``),
			want: map[string][]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPluginEndpointsFromData(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPluginEndpointsFromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadPluginEndpointsFromData() = %v, want %v", got, tt.want)
			}
		})
	}
}

type compareDetection struct {
	Plugins  map[string]PluginData
	Detected []string
}

func toCompare(d PluginDetectionResult) compareDetection {
	res := compareDetection{
		Plugins:  make(map[string]PluginData),
		Detected: append([]string(nil), d.Detected...),
	}
	sort.Strings(res.Detected)
	for k, v := range d.Plugins {
		if v != nil {
			tmp := *v
			sort.Strings(tmp.Matches)
			res.Plugins[k] = tmp
		}
	}
	return res
}

func compareDetections(a, b compareDetection) bool {
	if !reflect.DeepEqual(a.Detected, b.Detected) {
		return false
	}
	if len(a.Plugins) != len(b.Plugins) {
		return false
	}
	for k, va := range a.Plugins {
		vb, ok := b.Plugins[k]
		if !ok {
			return false
		}
		if va.Score != vb.Score || va.Ambiguous != vb.Ambiguous ||
			!reflect.DeepEqual(va.Matches, vb.Matches) {
			return false
		}
		if fmt.Sprintf("%.2f", va.Confidence) != fmt.Sprintf("%.2f", vb.Confidence) {
			return false
		}
	}
	return true
}

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
