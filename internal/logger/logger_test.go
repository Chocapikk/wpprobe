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

package logger

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger()
	if logger == nil {
		t.Errorf("NewLogger() returned nil")
	}
}

func Test_formatTime(t *testing.T) {
	got := formatTime()
	if got == "" {
		t.Errorf("formatTime() returned empty string")
	}
}

func TestLogger_Info(t *testing.T) {
	var buf bytes.Buffer
	originalLogger := DefaultLogger.Logger
	DefaultLogger.Logger = log.New(&buf, "", 0)
	defer func() { DefaultLogger.Logger = originalLogger }()

	msg := "This is an info message"
	DefaultLogger.Info(msg)

	if !strings.Contains(buf.String(), "INFO") || !strings.Contains(buf.String(), msg) {
		t.Errorf("Info() log = %v, want to contain 'INFO' and message", buf.String())
	}
}

func TestLogger_Warning(t *testing.T) {
	var buf bytes.Buffer
	originalLogger := DefaultLogger.Logger
	DefaultLogger.Logger = log.New(&buf, "", 0)
	defer func() { DefaultLogger.Logger = originalLogger }()

	msg := "This is a warning message"
	DefaultLogger.Warning(msg)

	if !strings.Contains(buf.String(), "WARNING") || !strings.Contains(buf.String(), msg) {
		t.Errorf("Warning() log = %v, want to contain 'WARNING' and message", buf.String())
	}
}

func TestLogger_Error(t *testing.T) {
	var buf bytes.Buffer
	originalLogger := DefaultLogger.Logger
	DefaultLogger.Logger = log.New(&buf, "", 0)
	defer func() { DefaultLogger.Logger = originalLogger }()

	msg := "This is an error message"
	DefaultLogger.Error(msg)

	if !strings.Contains(buf.String(), "ERROR") || !strings.Contains(buf.String(), msg) {
		t.Errorf("Error() log = %v, want to contain 'ERROR' and message", buf.String())
	}
}

func TestLogger_Success(t *testing.T) {
	var buf bytes.Buffer
	originalLogger := DefaultLogger.Logger
	DefaultLogger.Logger = log.New(&buf, "", 0)
	defer func() { DefaultLogger.Logger = originalLogger }()

	msg := "This is a success message"
	DefaultLogger.Success(msg)

	if !strings.Contains(buf.String(), "SUCCESS") || !strings.Contains(buf.String(), msg) {
		t.Errorf("Success() log = %v, want to contain 'SUCCESS' and message", buf.String())
	}
}

func TestLogger_PrintBanner(t *testing.T) {
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	version := "v1.0.0"
	isLatest := true
	DefaultLogger.PrintBanner(version, isLatest)
	_ = w.Close()

	var outBuf bytes.Buffer
	_, _ = outBuf.ReadFrom(r)
	os.Stdout = originalStdout

	output := outBuf.String()
	if !strings.Contains(output, version) || !strings.Contains(output, "latest") {
		t.Errorf("PrintBanner() output = %v, want version %v and 'latest'", output, version)
	}

	r, w, _ = os.Pipe()
	os.Stdout = w

	DefaultLogger.PrintBanner(version, false)
	_ = w.Close()

	outBuf.Reset()
	_, _ = outBuf.ReadFrom(r)
	os.Stdout = originalStdout

	output = outBuf.String()
	if !strings.Contains(output, "outdated") {
		t.Errorf("PrintBanner() output = %v, want 'outdated'", output)
	}
}
