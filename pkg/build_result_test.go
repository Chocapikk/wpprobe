package wpprobe

import (
	"testing"

	"github.com/Chocapikk/wpprobe/internal/file"
)

func TestBuildResult_IncludesPluginsWithoutVulnerabilities(t *testing.T) {
	s := &Scanner{}
	entries := []file.PluginEntry{
		{Slug: "safe-plugin", SoftwareType: "plugin", Version: "1.0.0"},
	}

	result := s.buildResult("http://example.com", entries)

	if len(result.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(result.Plugins))
	}
	if result.Plugins[0].Name != "safe-plugin" {
		t.Errorf("expected plugin name 'safe-plugin', got %q", result.Plugins[0].Name)
	}
	if result.TotalVulnerabilities != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", result.TotalVulnerabilities)
	}
}

func TestBuildResult_IncludesThemesWithoutVulnerabilities(t *testing.T) {
	s := &Scanner{}
	entries := []file.PluginEntry{
		{Slug: "safe-theme", SoftwareType: "theme", Version: "2.0.0"},
	}

	result := s.buildResult("http://example.com", entries)

	if len(result.Themes) != 1 {
		t.Fatalf("expected 1 theme, got %d", len(result.Themes))
	}
	if result.Themes[0].Name != "safe-theme" {
		t.Errorf("expected theme name 'safe-theme', got %q", result.Themes[0].Name)
	}
}

func TestBuildResult_MixesVulnerableAndSafe(t *testing.T) {
	s := &Scanner{}
	entries := []file.PluginEntry{
		{Slug: "safe-plugin", SoftwareType: "plugin", Version: "1.0.0"},
		{Slug: "vuln-plugin", SoftwareType: "plugin", Version: "1.2.0",
			Severity: "high", CVEs: []string{"CVE-2024-1234"}, Title: "RCE", AuthType: "unauth"},
		{Slug: "safe-theme", SoftwareType: "theme", Version: "3.0.0"},
	}

	result := s.buildResult("http://example.com", entries)

	if len(result.Plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(result.Plugins))
	}
	if len(result.Themes) != 1 {
		t.Fatalf("expected 1 theme, got %d", len(result.Themes))
	}
	if result.TotalVulnerabilities != 1 {
		t.Errorf("expected 1 vulnerability, got %d", result.TotalVulnerabilities)
	}
}

func TestBuildResult_SkipsUnknownVersions(t *testing.T) {
	s := &Scanner{}
	entries := []file.PluginEntry{
		{Slug: "no-version", SoftwareType: "plugin", Version: ""},
		{Slug: "unknown-version", SoftwareType: "plugin", Version: "unknown"},
		{Slug: "valid", SoftwareType: "plugin", Version: "1.0.0"},
	}

	result := s.buildResult("http://example.com", entries)

	if len(result.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(result.Plugins))
	}
	if result.Plugins[0].Name != "valid" {
		t.Errorf("expected plugin name 'valid', got %q", result.Plugins[0].Name)
	}
}

func TestBuildResult_DeduplicatesCVEs(t *testing.T) {
	s := &Scanner{}
	entries := []file.PluginEntry{
		{Slug: "plugin-a", SoftwareType: "plugin", Version: "1.0.0",
			Severity: "critical", CVEs: []string{"CVE-2024-0001"}, Title: "SQLi", AuthType: "unauth"},
		{Slug: "plugin-a", SoftwareType: "plugin", Version: "1.0.0",
			Severity: "critical", CVEs: []string{"CVE-2024-0001"}, Title: "SQLi", AuthType: "unauth"},
	}

	result := s.buildResult("http://example.com", entries)

	if len(result.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(result.Plugins))
	}
	if len(result.Plugins[0].Vulnerabilities.Critical) != 1 {
		t.Errorf("expected 1 critical vuln (deduped), got %d", len(result.Plugins[0].Vulnerabilities.Critical))
	}
}
