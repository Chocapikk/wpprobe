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
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type WriterInterface interface {
	WriteResults(url string, results []PluginEntry)
	Close()
}

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

func authTypeOrder(auth string) int {
	switch strings.ToLower(auth) {
	case "unauth":
		return 0
	case "auth":
		return 1
	default:
		return 2
	}
}

//////////////////////////////
// CSV Writer Implementation
//////////////////////////////

type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
	mu     sync.Mutex
}

func NewCSVWriter(filename string) *CSVWriter {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		DefaultLogger.Error("Failed to open CSV file: " + err.Error())
	}
	writer := csv.NewWriter(file)
	header := []string{
		"URL",
		"Plugin",
		"Version",
		"Severity",
		"AuthType",
		"CVEs",
		"CVE Links",
		"CVSS Score",
		"CVSS Vector",
		"Title",
	}
	_ = writer.Write(header)
	writer.Flush()
	return &CSVWriter{file: file, writer: writer}
}

func (c *CSVWriter) WriteResults(url string, results []PluginEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	severityOrder := map[string]int{
		"critical": 1,
		"high":     2,
		"medium":   3,
		"low":      4,
		"unknown":  5,
		"N/A":      6,
	}

	sort.Slice(results, func(i, j int) bool {
		si, sj := severityOrder[results[i].Severity], severityOrder[results[j].Severity]
		if si != sj {
			return si < sj
		}
		return authTypeOrder(results[i].AuthType) < authTypeOrder(results[j].AuthType)
	})

	for _, entry := range results {
		row := []string{
			url,
			entry.Plugin,
			entry.Version,
			entry.Severity,
			entry.AuthType,
			strings.Join(entry.CVEs, ", "),
			strings.Join(entry.CVELinks, ", "),
			fmt.Sprintf("%.1f", entry.CVSSScore),
			entry.CVSSVector,
			entry.Title,
		}
		_ = c.writer.Write(row)
	}
	c.writer.Flush()
}

func (c *CSVWriter) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writer.Flush()
	_ = c.file.Close()
}

//////////////////////////////
// JSON Writer Implementation
//////////////////////////////

type Vulnerability struct {
	CVE        string  `json:"cve"`
	CVELink    string  `json:"cve_link"`
	Title      string  `json:"title"`
	CVSSScore  float64 `json:"cvss_score"`
	CVSSVector string  `json:"cvss_vector"`
}

type AuthGroup struct {
	AuthType        string          `json:"auth_type"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type SeverityEntry struct {
	Severity string
	Auths    []AuthGroup
}

func (s SeverityEntry) MarshalJSON() ([]byte, error) {
	m := map[string][]AuthGroup{
		strings.ToLower(s.Severity): s.Auths,
	}
	return json.Marshal(m)
}

type VersionGroup struct {
	Version    string          `json:"version"`
	Severities []SeverityEntry `json:"severities"`
}

type PluginResult struct {
	Name     string         `json:"-"`
	Versions []VersionGroup `json:"versions"`
}

type PluginsCollection []PluginResult

func (p PluginsCollection) MarshalJSON() ([]byte, error) {
	m := make(map[string][]VersionGroup)
	for _, pr := range p {
		m[pr.Name] = pr.Versions
	}
	return json.Marshal(m)
}

type OutputResults struct {
	URL     string            `json:"url"`
	Plugins PluginsCollection `json:"plugins"`
}

type JSONWriter struct {
	file  *os.File
	mu    sync.Mutex
	first bool
}

func NewJSONWriter(output string) *JSONWriter {
	file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		DefaultLogger.Error("Failed to open JSON file: " + err.Error())
		os.Exit(1)
	}
	return &JSONWriter{file: file}
}

func (j *JSONWriter) WriteResults(url string, results []PluginEntry) {
	j.mu.Lock()
	defer j.mu.Unlock()

	pluginResultsMap := make(map[string]*PluginResult)
	detectedPlugins := make(map[string]bool)

	for _, entry := range results {
		pluginName := entry.Plugin
		version := entry.Version
		severity := entry.Severity
		auth := strings.ToLower(entry.AuthType)

		detectedPlugins[pluginName] = true

		if severity == "" || severity == "N/A" {
			continue
		}

		if auth != "auth" && auth != "unauth" && auth != "privileged" {
			auth = "unknown"
		}
		authFormatted := cases.Title(language.Und).String(auth)

		vuln := Vulnerability{
			CVE:        "",
			CVELink:    "",
			Title:      entry.Title,
			CVSSScore:  entry.CVSSScore,
			CVSSVector: entry.CVSSVector,
		}

		if len(entry.CVEs) > 0 {
			vuln.CVE = entry.CVEs[0]
		}
		if len(entry.CVELinks) > 0 {
			vuln.CVELink = entry.CVELinks[0]
		}

		pr, ok := pluginResultsMap[pluginName]
		if !ok {
			pr = &PluginResult{Name: pluginName, Versions: []VersionGroup{}}
			pluginResultsMap[pluginName] = pr
		}

		var vg *VersionGroup
		for i := range pr.Versions {
			if pr.Versions[i].Version == version {
				vg = &pr.Versions[i]
				break
			}
		}
		if vg == nil {
			pr.Versions = append(pr.Versions, VersionGroup{
				Version:    version,
				Severities: []SeverityEntry{},
			})
			vg = &pr.Versions[len(pr.Versions)-1]
		}

		var se *SeverityEntry
		for i := range vg.Severities {
			if vg.Severities[i].Severity == severity {
				se = &vg.Severities[i]
				break
			}
		}
		if se == nil {
			vg.Severities = append(vg.Severities, SeverityEntry{
				Severity: severity,
				Auths:    []AuthGroup{},
			})
			se = &vg.Severities[len(vg.Severities)-1]
		}

		se.Auths = append(se.Auths, AuthGroup{
			AuthType:        authFormatted,
			Vulnerabilities: []Vulnerability{vuln},
		})

		sort.Slice(vg.Severities, func(i, j int) bool {
			severityOrder := map[string]int{
				"critical": 1,
				"high":     2,
				"medium":   3,
				"low":      4,
				"unknown":  5,
				"N/A":      6,
			}
			return severityOrder[strings.ToLower(vg.Severities[i].Severity)] <
				severityOrder[strings.ToLower(vg.Severities[j].Severity)]
		})
	}

	for pluginName := range detectedPlugins {
		if _, exists := pluginResultsMap[pluginName]; !exists {
			pluginResultsMap[pluginName] = &PluginResult{
				Name: pluginName,
				Versions: []VersionGroup{
					{
						Version:    "unknown",
						Severities: []SeverityEntry{},
					},
				},
			}
		}
	}

	var pluginsColl PluginsCollection
	for _, pr := range pluginResultsMap {
		pluginsColl = append(pluginsColl, *pr)
	}

	outputEntry := OutputResults{
		URL:     url,
		Plugins: pluginsColl,
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	_ = encoder.Encode(outputEntry)

	data := buffer.Bytes()
	if len(data) > 0 {
		data = data[:len(data)-1]
	}
	if !j.first {
		_, _ = j.file.WriteString("\n")
	}
	j.first = false
	_, _ = j.file.Write(data)
}

func (j *JSONWriter) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.file.Close()
}

//////////////////////////////
// Writer Factory
//////////////////////////////

func DetectOutputFormat(outputFile string) string {
	if outputFile == "" {
		return "csv"
	}
	ext := strings.TrimPrefix(filepath.Ext(outputFile), ".")
	supported := []string{"csv", "json"}
	for _, format := range supported {
		if ext == format {
			return format
		}
	}
	fmt.Printf("⚠️ Unsupported output format: %s. Defaulting to CSV.\n", ext)
	return "csv"
}

func GetWriter(outputFile string) WriterInterface {
	if strings.HasSuffix(outputFile, ".json") {
		return NewJSONWriter(outputFile)
	}
	return NewCSVWriter(outputFile)
}

//////////////////////////////
// Utils
//////////////////////////////

func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		DefaultLogger.Error("Failed to open file: " + err.Error())
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		DefaultLogger.Error("Failed to read lines: " + err.Error())
		return nil, err
	}
	return lines, nil
}

func GetStoragePath(filename string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		DefaultLogger.Error("Failed to get config directory: " + err.Error())
		return "", err
	}
	storagePath := filepath.Join(configDir, "wpprobe")
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		DefaultLogger.Error("Failed to create storage directory: " + err.Error())
		return "", err
	}
	return filepath.Join(storagePath, filename), nil
}
