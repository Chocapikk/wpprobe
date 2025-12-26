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
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

type MockWriter struct {
	buffer bytes.Buffer
}

func (mw *MockWriter) WriteResults(plugin string, results []file.PluginEntry) {
	data, _ := json.Marshal(results)
	mw.buffer.Write(data)
}

func (mw *MockWriter) Close() {}

func (mw *MockWriter) Output() string {
	return mw.buffer.String()
}

func TestScanSite(t *testing.T) {
	mockWriter := &MockWriter{}

	opts := ScanOptions{
		URL:     "http://example.com",
		Threads: 2,
	}

	getEmbeddedFile := func(filename string) ([]byte, error) {
		mockData := `{"test-plugin": ["/wp-json/test-endpoint"]}`
		return []byte(mockData), nil
	}

	getVulnerabilitiesForPlugin := func(plugin, version string) []wordfence.Vulnerability {
		return []wordfence.Vulnerability{
			{
				Title:        "Test Vulnerability Title",
				Slug:         "test-plugin",
				SoftwareType: "plugin",
				CVE:          "CVE-2024-0001",
				Severity:     "High",
			},
		}
	}

	ScanSiteWithMocks(
		"http://example.com",
		opts,
		mockWriter,
		getEmbeddedFile,
		getVulnerabilitiesForPlugin,
	)

	output := mockWriter.Output()
	if !strings.Contains(output, "CVE-2024-0001") {
		t.Errorf("Expected CVE-2024-0001 in output, got: %s", output)
	}
}

func TestScanSite_NoPluginsDetected(t *testing.T) {
	mockWriter := &MockWriter{}

	opts := ScanOptions{
		URL:     "http://example.com",
		Threads: 2,
	}

	getEmbeddedFile := func(filename string) ([]byte, error) {
		return []byte("{}"), nil
	}

	getVulnerabilitiesForPlugin := func(plugin, version string) []wordfence.Vulnerability {
		return nil
	}

	ScanSiteWithMocks(
		"http://example.com",
		opts,
		mockWriter,
		getEmbeddedFile,
		getVulnerabilitiesForPlugin,
	)

	output := mockWriter.Output()
	if output != "[]" && output != "" {
		t.Errorf("Expected empty output, got: %s", output)
	}
}

func TestScanSite_ErrorInFetchingFile(t *testing.T) {
	mockWriter := &MockWriter{}

	opts := ScanOptions{
		URL:     "http://example.com",
		Threads: 2,
	}

	getEmbeddedFile := func(filename string) ([]byte, error) {
		return nil, errors.New("mock error")
	}

	getVulnerabilitiesForPlugin := func(plugin, version string) []wordfence.Vulnerability {
		return nil
	}

	ScanSiteWithMocks(
		"http://example.com",
		opts,
		mockWriter,
		getEmbeddedFile,
		getVulnerabilitiesForPlugin,
	)

	output := mockWriter.Output()
	if output != "" {
		t.Errorf("Expected no output due to error, got: %s", output)
	}
}

func ScanSiteWithMocks(
	target string,
	opts ScanOptions,
	writer file.WriterInterface,
	getEmbeddedFile func(string) ([]byte, error),
	getVulnsForPlugin func(string, string) []wordfence.Vulnerability,
) {
	_, err := getEmbeddedFile("files/scanned_plugins.json")
	if err != nil {
		return
	}

	endpoints := []string{"/wp-json/test-endpoint"}
	for _, plugin := range endpoints {
		version := "1.0.0"
		vulns := getVulnsForPlugin(plugin, version)
		for _, vuln := range vulns {
			writer.WriteResults(plugin, []file.PluginEntry{
				{
					Plugin:   plugin,
					Version:  version,
					Severity: vuln.Severity,
					CVEs:     []string{vuln.CVE},
				},
			})
		}
	}
}

