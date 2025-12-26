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

package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestExecute(t *testing.T) {
	tests := []struct {
		name    string
		wantOut string
	}{
		{
			name:    "Execute Command",
			wantOut: "WPProbe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			defer func() {
				os.Stdout = oldStdout
				_ = w.Close()
			}()

			go func() {
				Execute()
				_ = w.Close()
			}()

			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r)
			output := buf.String()

			if !strings.Contains(output, tt.wantOut) {
				t.Errorf("Execute() output = %v, want to contain %v", output, tt.wantOut)
			}
		})
	}
}

func TestRootCmd_Help(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectOut   []string
	}{
		{
			name:        "Display Help",
			args:        []string{"--help"},
			expectError: false,
			expectOut:   []string{"Usage:", "WPProbe is a high-speed WordPress plugin scanner"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := rootCmd
			output := new(bytes.Buffer)
			cmd.SetOut(output)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			for _, str := range tt.expectOut {
				if !strings.Contains(output.String(), str) {
					t.Errorf("Help output missing expected string %v", str)
				}
			}
		})
	}
}
