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
			name: "Valid JSON with single plugin",
			data: []byte(`{"plugin1": ["/endpoint1", "/endpoint2"]}`),
			want: map[string][]string{
				"plugin1": {"/endpoint1", "/endpoint2"},
			},
			wantErr: false,
		},
		{
			name: "Valid JSON with multiple plugins",
			data: []byte(`{"plugin1": ["/endpoint1"], "plugin2": ["/endpoint2", "/endpoint3"]}`),
			want: map[string][]string{
				"plugin1": {"/endpoint1"},
				"plugin2": {"/endpoint2", "/endpoint3"},
			},
			wantErr: false,
		},
		{
			name:    "Empty JSON",
			data:    []byte(`{}`),
			want:    map[string][]string{},
			wantErr: false,
		},
		{
			name:    "Invalid JSON",
			data:    []byte(`{invalid json}`),
			want:    map[string][]string{},
			wantErr: false,
		},
		{
			name:    "Empty data",
			data:    []byte(``),
			want:    map[string][]string{},
			wantErr: false,
		},
		{
			name: "Plugin with empty endpoints",
			data: []byte(`{"plugin1": []}`),
			want: map[string][]string{
				"plugin1": {},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadPluginEndpointsFromData(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPluginEndpointsFromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !mapsEqual(got, tt.want) {
				t.Errorf("LoadPluginEndpointsFromData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mapsEqual(a, b map[string][]string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slicesEqual(v, b[k]) {
			return false
		}
	}
	return true
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

