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
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Chocapikk/wpprobe/internal/utils"
)

var logger = utils.NewLogger()

const wordfenceAPI = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"

type Vulnerability struct {
	Title           string `json:"title"`
	Slug            string `json:"slug"`
	SoftwareType    string `json:"type"`
	AffectedVersion string `json:"affected_version"`
	FromVersion     string `json:"from_version"`
	FromInclusive   bool   `json:"from_inclusive"`
	ToVersion       string `json:"to_version"`
	ToInclusive     bool   `json:"to_inclusive"`
	Severity        string `json:"severity"`
	CVE             string `json:"cve"`
	CVELink         string `json:"cve_link"`
	AuthType        string `json:"auth_type"`
}

func UpdateWordfence() error {
	logger.Info("Fetching Wordfence data...")

	data, err := fetchWordfenceData()
	if err != nil {
		handleFetchError(err)
		return err
	}

	logger.Info("Processing vulnerabilities...")
	vulnerabilities := processWordfenceData(data)

	logger.Info("Saving vulnerabilities to file...")
	if err := saveVulnerabilitiesToFile(vulnerabilities); err != nil {
		logger.Error("Failed to save Wordfence data: " + err.Error())
		return err
	}

	logger.Success("Wordfence data updated successfully!")
	return nil
}

func fetchWordfenceData() (map[string]interface{}, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(wordfenceAPI)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		logger.Info("Decoding JSON data... This may take some time.")
		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("JSON decoding error: %w", err)
		}
		logger.Success("Successfully retrieved and processed Wordfence data.")
		return data, nil

	case http.StatusTooManyRequests:
		retryAfter := resp.Header.Get("Retry-After")
		if retryAfter == "" {
			retryAfter = "a few minutes"
		}
		return nil, fmt.Errorf("rate limit exceeded (429). Retry after %s", retryAfter)

	default:
		return nil, fmt.Errorf(
			"unexpected API status: %d %s",
			resp.StatusCode,
			http.StatusText(resp.StatusCode),
		)
	}
}

func handleFetchError(err error) {
	switch {
	case strings.Contains(err.Error(), "429"):
		logger.Warning("Wordfence API rate limit hit (429). Please wait before retrying.")
	default:
		logger.Error("Failed to retrieve Wordfence data: " + err.Error())
	}
}

func processWordfenceData(wfData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, vulnerability := range wfData {
		vulnMap, ok := vulnerability.(map[string]interface{})
		if !ok {
			continue
		}

		title, _ := vulnMap["title"].(string)
		authType := "Unknown"
		lowerTitle := strings.ToLower(title)
		if strings.Contains(lowerTitle, "unauth") {
			authType = "Unauth"
		} else if strings.Contains(lowerTitle, "auth") {
			authType = "Auth"
		}

		for _, software := range vulnMap["software"].([]interface{}) {
			softMap, ok := software.(map[string]interface{})
			if !ok {
				continue
			}

			slug, _ := softMap["slug"].(string)
			cve, _ := vulnMap["cve"].(string)
			cveLink, _ := vulnMap["cve_link"].(string)
			softwareType, _ := softMap["type"].(string)

			if cve == "" {
				continue
			}

			affectedVersions, ok := softMap["affected_versions"].(map[string]interface{})
			if !ok {
				continue
			}

			for versionLabel, affectedVersionData := range affectedVersions {
				affectedVersion, ok := affectedVersionData.(map[string]interface{})
				if !ok {
					continue
				}

				fromVersion := strings.ReplaceAll(
					affectedVersion["from_version"].(string),
					"*",
					"0.0.0",
				)
				toVersion := strings.ReplaceAll(
					affectedVersion["to_version"].(string),
					"*",
					"999999.0.0",
				)

				vuln := Vulnerability{
					Title:           title,
					Slug:            slug,
					SoftwareType:    softwareType,
					AffectedVersion: versionLabel,
					FromVersion:     fromVersion,
					FromInclusive:   affectedVersion["from_inclusive"].(bool),
					ToVersion:       toVersion,
					ToInclusive:     affectedVersion["to_inclusive"].(bool),
					Severity: strings.ToLower(
						vulnMap["cvss"].(map[string]interface{})["rating"].(string),
					),
					CVE:      cve,
					CVELink:  cveLink,
					AuthType: authType,
				}

				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

func saveVulnerabilitiesToFile(vulnerabilities []Vulnerability) error {
	outputPath, err := utils.GetStoragePath("wordfence_vulnerabilities.json")
	if err != nil {
		logger.Error("Error getting storage path: " + err.Error())
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		logger.Error("Error saving file: " + err.Error())
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(vulnerabilities); err != nil {
		logger.Error("Error encoding JSON: " + err.Error())
		return err
	}

	logger.Success("Wordfence data saved in " + outputPath)
	return nil
}

func LoadVulnerabilities(filename string) ([]Vulnerability, error) {
	filePath, err := utils.GetStoragePath(filename)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vulnerabilities []Vulnerability
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&vulnerabilities); err != nil {
		return nil, err
	}

	return vulnerabilities, nil
}

func GetVulnerabilitiesForPlugin(plugin string, version string) []Vulnerability {
	vulnerabilities := []Vulnerability{}

	data, err := LoadVulnerabilities("wordfence_vulnerabilities.json")
	if err != nil {
		return vulnerabilities
	}

	for _, vuln := range data {
		if vuln.CVE == "" {
			continue
		}

		if vuln.Slug == plugin {
			if utils.IsVersionVulnerable(version, vuln.FromVersion, vuln.ToVersion) {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}
