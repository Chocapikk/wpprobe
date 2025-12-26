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
	"encoding/json"
	"strings"
)

// WriterInterface defines the interface for writing scan results.
type WriterInterface interface {
	WriteResults(url string, results []PluginEntry)
	Close()
}

// PluginEntry represents a plugin entry with its vulnerabilities.
type PluginEntry struct {
	Plugin     string   `json:"plugin"`
	Version    string   `json:"version"`
	Severity   string   `json:"severity"`
	CVEs       []string `json:"cves"`
	CVELinks   []string `json:"cve_link"`
	Title      string   `json:"title"`
	AuthType   string   `json:"auth_type"`
	CVSSScore  float64  `json:"cvss_score"`
	CVSSVector string   `json:"cvss_vector"`
}

// Vulnerability represents a vulnerability entry.
type Vulnerability struct {
	CVE        string  `json:"cve"`
	CVELink    string  `json:"cve_link"`
	Title      string  `json:"title"`
	CVSSScore  float64 `json:"cvss_score"`
	CVSSVector string  `json:"cvss_vector"`
}

// AuthGroup groups vulnerabilities by authentication type.
type AuthGroup struct {
	AuthType        string          `json:"auth_type"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// SeverityEntry groups vulnerabilities by severity and auth type.
type SeverityEntry struct {
	Severity string
	Auths    []AuthGroup
}

// MarshalJSON implements custom JSON marshaling for SeverityEntry.
func (s SeverityEntry) MarshalJSON() ([]byte, error) {
	m := map[string][]AuthGroup{
		strings.ToLower(s.Severity): s.Auths,
	}
	return json.Marshal(m)
}

// VersionGroup groups vulnerabilities by version.
type VersionGroup struct {
	Version    string          `json:"version"`
	Severities []SeverityEntry `json:"severities"`
}

// PluginResult represents a plugin with its version groups.
type PluginResult struct {
	Name     string         `json:"-"`
	Versions []VersionGroup `json:"versions"`
}

// PluginsCollection is a collection of plugin results.
type PluginsCollection []PluginResult

// MarshalJSON implements custom JSON marshaling for PluginsCollection.
func (p PluginsCollection) MarshalJSON() ([]byte, error) {
	m := make(map[string][]VersionGroup)
	for _, pr := range p {
		m[pr.Name] = pr.Versions
	}
	return json.Marshal(m)
}

// OutputResults represents the complete output structure.
type OutputResults struct {
	URL     string            `json:"url"`
	Plugins PluginsCollection `json:"plugins"`
}

