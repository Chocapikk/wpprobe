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

package wordfence

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/utils"
)

func TestUpdateWordfence(t *testing.T) {
	err := UpdateWordfence()
	if err != nil {
		t.Errorf("UpdateWordfence() returned error: %v", err)
	}

	outputPath, _ := utils.GetStoragePath("wordfence_vulnerabilities.json")
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("Expected file %s to be created", outputPath)
	}

	os.Remove(outputPath)
}

func Test_processWordfenceData(t *testing.T) {
	mockData := map[string]interface{}{
		"vuln1": map[string]interface{}{
			"title":    "Unauthenticated ZBEUB",
			"cve":      "CVE-2024-0001",
			"cve_link": "https://example.com/cve/CVE-2024-0001",
			"cvss": map[string]interface{}{
				"rating": "High",
			},
			"software": []interface{}{
				map[string]interface{}{
					"slug": "test-plugin",
					"type": "plugin",
					"affected_versions": map[string]interface{}{
						"1.0.0 - 2.0.0": map[string]interface{}{
							"from_version":   "1.0.0",
							"to_version":     "2.0.0",
							"from_inclusive": true,
							"to_inclusive":   true,
						},
					},
				},
			},
		},
	}

	want := []Vulnerability{
		{
			Title:           "Unauthenticated ZBEUB",
			Slug:            "test-plugin",
			SoftwareType:    "plugin",
			AffectedVersion: "1.0.0 - 2.0.0",
			FromVersion:     "1.0.0",
			FromInclusive:   true,
			ToVersion:       "2.0.0",
			ToInclusive:     true,
			Severity:        "high",
			CVE:             "CVE-2024-0001",
			CVELink:         "https://example.com/cve/CVE-2024-0001",
			AuthType:        "Unauth",
		},
	}

	got := processWordfenceData(mockData)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("processWordfenceData() = %v, want %v", got, want)
	}
}

func Test_saveVulnerabilitiesToFile(t *testing.T) {
	vulnerabilities := []Vulnerability{
		{
			Title:        "Test Vulnerability Title",
			Slug:         "test-plugin",
			SoftwareType: "plugin",
			CVE:          "CVE-2024-0001",
		},
	}

	err := saveVulnerabilitiesToFile(vulnerabilities)
	if err != nil {
		t.Errorf("saveVulnerabilitiesToFile() error = %v, want nil", err)
	}

	outputPath, _ := utils.GetStoragePath("wordfence_vulnerabilities.json")
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("Expected file %s to be created", outputPath)
	}

	os.Remove(outputPath)
}

func Test_LoadVulnerabilities(t *testing.T) {
	vulnerabilities := []Vulnerability{
		{
			Title:        "Test Vulnerability Title",
			Slug:         "test-plugin",
			SoftwareType: "plugin",
			CVE:          "CVE-2024-0001",
		},
	}

	outputPath, err := utils.GetStoragePath("wordfence_vulnerabilities.json")
	if err != nil {
		t.Fatalf("Failed to get storage path: %v", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(vulnerabilities); err != nil {
		t.Fatalf("Failed to encode vulnerabilities: %v", err)
	}

	loadedVulns, err := LoadVulnerabilities("wordfence_vulnerabilities.json")
	if err != nil {
		t.Fatalf("Failed to load vulnerabilities: %v", err)
	}

	if len(loadedVulns) != len(vulnerabilities) {
		t.Errorf("Expected %d vulnerabilities, got %d", len(vulnerabilities), len(loadedVulns))
	}

	for i, vuln := range vulnerabilities {
		if !reflect.DeepEqual(vuln, loadedVulns[i]) {
			t.Errorf("Mismatch at index %d: got %+v, want %+v", i, loadedVulns[i], vuln)
		}
	}
}

func TestGetVulnerabilitiesForPlugin(t *testing.T) {
	vulnerabilities := []Vulnerability{
		{
			Title:        "Test Vulnerability Title",
			Slug:         "test-plugin",
			SoftwareType: "plugin",
			FromVersion:  "1.0.0",
			ToVersion:    "2.0.0",
			CVE:          "CVE-2024-0001",
		},
	}

	outputPath, err := utils.GetStoragePath("wordfence_vulnerabilities.json")
	if err != nil {
		t.Fatalf("Failed to get storage path: %v", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(vulnerabilities); err != nil {
		t.Fatalf("Failed to encode vulnerabilities: %v", err)
	}

	got := GetVulnerabilitiesForPlugin("test-plugin", "1.5.0")

	if len(got) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(got))
	}

	if got[0].CVE != "CVE-2024-0001" {
		t.Errorf("Expected CVE-2024-0001, got %s", got[0].CVE)
	}

	if err := os.Remove(outputPath); err != nil {
		t.Errorf("Failed to remove test file: %v", err)
	}
}
