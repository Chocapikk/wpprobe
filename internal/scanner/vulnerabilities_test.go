package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

func TestCheckVulnerabilities_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	plugins := make([]string, 100)
	for i := range plugins {
		plugins[i] = "fake-plugin"
	}

	req := VulnerabilityCheckRequest{
		Plugins: plugins,
		Target:  "http://example.com",
		Vulns:   nil,
		Opts: ScanOptions{
			Threads:        2,
			NoCheckVersion: true,
		},
		Ctx: ctx,
	}

	done := make(chan struct{})
	go func() {
		CheckVulnerabilities(req)
		close(done)
	}()

	select {
	case <-done:
		// Returned promptly, context cancellation worked
	case <-time.After(5 * time.Second):
		t.Fatal("CheckVulnerabilities did not return promptly after context cancellation")
	}
}

func TestCheckVulnerabilities_NilContext(t *testing.T) {
	plugins := []string{"test-plugin"}

	req := VulnerabilityCheckRequest{
		Plugins: plugins,
		Target:  "http://example.com",
		Vulns:   nil,
		Opts: ScanOptions{
			Threads:        2,
			NoCheckVersion: true,
		},
		Versions: map[string]string{"test-plugin": "1.0.0"},
		Ctx:      nil, // nil context should not panic
	}

	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("CheckVulnerabilities panicked with nil context: %v", r)
			}
			close(done)
		}()
		CheckVulnerabilities(req)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CheckVulnerabilities timed out with nil context")
	}
}

func TestCheckVulnerabilities_PreDetectedVersions(t *testing.T) {
	plugins := []string{"known-plugin"}
	versions := map[string]string{"known-plugin": "2.0.0"}

	req := VulnerabilityCheckRequest{
		Plugins: plugins,
		Target:  "http://example.com",
		Vulns: []wordfence.Vulnerability{
			{
				Slug:        "known-plugin",
				CVE:         "CVE-2024-9999",
				Title:       "Test Vuln",
				Severity:    "high",
				FromVersion: "1.0.0",
				ToVersion:   "3.0.0",
			},
		},
		Opts: ScanOptions{
			Threads:        2,
			NoCheckVersion: false,
		},
		Versions: versions,
		Ctx:      context.Background(),
	}

	entriesMap, entriesList := CheckVulnerabilities(req)

	if _, ok := entriesMap["known-plugin"]; !ok {
		t.Error("Expected known-plugin in entriesMap")
	}
	if entriesMap["known-plugin"] != "2.0.0" {
		t.Errorf("Version = %q, want %q", entriesMap["known-plugin"], "2.0.0")
	}

	foundCVE := false
	for _, entry := range entriesList {
		for _, cve := range entry.CVEs {
			if cve == "CVE-2024-9999" {
				foundCVE = true
			}
		}
	}
	if !foundCVE {
		t.Error("Expected CVE-2024-9999 in results")
	}
}

func TestBuildVulnerabilityIndex(t *testing.T) {
	vulns := []wordfence.Vulnerability{
		{Slug: "plugin-a", CVE: "CVE-1"},
		{Slug: "plugin-a", CVE: "CVE-2"},
		{Slug: "plugin-b", CVE: "CVE-3"},
		{Slug: "", CVE: "CVE-4"}, // empty slug should be skipped
	}

	index := buildVulnerabilityIndex(vulns)

	if len(index["plugin-a"]) != 2 {
		t.Errorf("plugin-a entries = %d, want 2", len(index["plugin-a"]))
	}
	if len(index["plugin-b"]) != 1 {
		t.Errorf("plugin-b entries = %d, want 1", len(index["plugin-b"]))
	}
	if _, ok := index[""]; ok {
		t.Error("Empty slug should not be in index")
	}
}
