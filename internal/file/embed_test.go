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

package file

import (
	"strings"
	"testing"
)

func TestGetEmbeddedFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantSub  string
		wantErr  bool
	}{
		{
			name:     "Valid file",
			filename: "files/scanned_plugins.json",
			wantSub:  `"3d-viewer"`,
			wantErr:  false,
		},
		{
			name:     "Non-existent file",
			filename: "files/nonexistent.json",
			wantSub:  "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetEmbeddedFile(tt.filename)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetEmbeddedFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !strings.Contains(string(got), tt.wantSub) {
				t.Errorf("Expected content to contain '%s', but got: %s", tt.wantSub, string(got))
			}
		})
	}
}
