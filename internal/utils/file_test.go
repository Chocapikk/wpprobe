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

package utils

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNewCSVWriter(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_output_*.csv")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	writer := NewCSVWriter(tmpFile.Name())
	if writer == nil {
		t.Fatal("Expected CSVWriter instance, got nil")
	}

	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Errorf("Expected file %s to be created", tmpFile.Name())
	}

	writer.Close()
}

func TestCSVWriter_WriteResults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_results_*.csv")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	writer := NewCSVWriter(tmpFile.Name())
	defer writer.Close()

	results := []PluginEntry{
		{
			Plugin:     "test-plugin",
			Version:    "1.0",
			Severity:   "High",
			AuthType:   "Unauth",
			CVEs:       []string{"CVE-1234"},
			CVELinks:   []string{"https://www.cve.org/CVERecord?id=CVE-1234"},
			CVSSScore:  9.8,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Title:      "Test Vulnerability",
		},
	}

	writer.WriteResults("http://example.com", results)
	writer.Close()

	file, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to open CSV: %v", err)
	}
	defer func() { _ = file.Close() }()

	r := csv.NewReader(file)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	t.Logf("CSV content: %v", records)

	if len(records) < 2 {
		t.Fatalf("Expected at least 2 rows (header + data), got %d", len(records))
	}

	if len(records[1]) < 10 {
		t.Fatalf("Expected at least 10 columns, got %d", len(records[1]))
	}

	if records[1][1] != "test-plugin" {
		t.Errorf("Expected plugin 'test-plugin', got %s", records[1][1])
	}
}

func TestNewJSONWriter(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_output_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	writer := NewJSONWriter(tmpFile.Name())
	if writer == nil {
		t.Fatal("Expected JSONWriter instance, got nil")
	}

	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Errorf("Expected file %s to be created", tmpFile.Name())
	}

	writer.Close()
}

func TestJSONWriter_WriteResults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_results_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	writer := NewJSONWriter(tmpFile.Name())
	defer writer.Close()

	results := []PluginEntry{
		{Plugin: "test-plugin", Version: "1.0", Severity: "High", CVEs: []string{"CVE-1234"}},
		{Plugin: "no-vuln-plugin", Version: "unknown", Severity: "N/A", CVEs: nil, CVELinks: nil},
	}

	writer.WriteResults("http://example.com", results)
	writer.Close()

	file, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read JSON: %v", err)
	}

	t.Logf("JSON file content: %s", string(file))

	var data map[string]interface{}
	err = json.Unmarshal(file, &data)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if data["url"] != "http://example.com" {
		t.Errorf("Expected URL 'http://example.com', got %v", data["url"])
	}

	plugins := data["plugins"].(map[string]interface{})
	if _, exists := plugins["test-plugin"]; !exists {
		t.Errorf("Expected 'test-plugin' in plugins, got %v", plugins)
	}

	if _, exists := plugins["no-vuln-plugin"]; !exists {
		t.Errorf("Expected 'no-vuln-plugin' in plugins, but it was missing")
	}
}

func TestGetWriter(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		wantType   string
	}{
		{"CSV format", "output.csv", "*utils.CSVWriter"},
		{"JSON format", "output.json", "*utils.JSONWriter"},
		{"Unsupported format", "output.txt", "*utils.CSVWriter"}, // Defaults to CSV
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := GetWriter(tt.outputFile)
			defer func() { _ = os.Remove(tt.outputFile) }()

			if reflect.TypeOf(writer).String() != tt.wantType {
				t.Errorf("GetWriter() = %T, want %s", writer, tt.wantType)
			}
		})
	}
}

func TestDetectOutputFormat(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		want       string
	}{
		{"CSV file", "output.csv", "csv"},
		{"JSON file", "output.json", "json"},
		{"No extension", "output", "csv"},
		{"Unsupported extension", "output.xml", "csv"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectOutputFormat(tt.outputFile); got != tt.want {
				t.Errorf("DetectOutputFormat() = %v, want %v", got, tt.want)
			} else {
				t.Logf("Correct format detected: %s", got)
			}
		})
	}
}

func TestReadLines(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_lines_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	content := "line1\nline2\nline3"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	defer func() { _ = tmpFile.Close() }()

	lines, err := ReadLines(tmpFile.Name())
	if err != nil {
		t.Fatalf("ReadLines() error = %v", err)
	}

	t.Logf("Read lines: %v", lines)

	expected := []string{"line1", "line2", "line3"}
	if !reflect.DeepEqual(lines, expected) {
		t.Errorf("ReadLines() = %v, want %v", lines, expected)
	}
}

func TestGetStoragePath(t *testing.T) {
	filename := "testfile.txt"
	path, err := GetStoragePath(filename)
	if err != nil {
		t.Fatalf("GetStoragePath() error = %v", err)
	}
	defer func() { _ = os.Remove(path) }()

	t.Logf("Generated storage path: %s", path)

	if !strings.Contains(path, filename) {
		t.Errorf("GetStoragePath() = %v, want to contain %v", path, filename)
	}

	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Errorf("Storage directory does not exist: %v", filepath.Dir(path))
	}
}
