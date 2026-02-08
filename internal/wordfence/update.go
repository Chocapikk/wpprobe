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
	nethttp "net/http"
	"strings"
	"time"

	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/vulnerability"
)

const wordfenceAPI = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"

// Vulnerability is an alias for the common vulnerability type.
type Vulnerability = vulnerability.Vulnerability

func UpdateWordfence() error {
	logger.DefaultLogger.Info("Fetching Wordfence data...")

	data, err := fetchWordfenceData()
	if err != nil {
		handleFetchError(err)
		return err
	}

	logger.DefaultLogger.Info("Processing vulnerabilities...")
	vulnerabilities := processWordfenceData(data)

	logger.DefaultLogger.Info("Saving vulnerabilities to file...")
	if err := vulnerability.SaveVulnerabilitiesToFile(vulnerabilities, "wordfence_vulnerabilities.json", "Wordfence"); err != nil {
		logger.DefaultLogger.Error("Failed to save Wordfence data: " + err.Error())
		return err
	}

	logger.DefaultLogger.Success("Wordfence data updated successfully!")
	return nil
}

func fetchWordfenceData() (map[string]interface{}, error) {
	client := &nethttp.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(wordfenceAPI)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case nethttp.StatusOK:
		logger.DefaultLogger.Info("Decoding JSON data... This may take some time.")
		var data map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("JSON decoding error: %w", err)
		}
		logger.DefaultLogger.Success("Successfully retrieved and processed Wordfence data.")
		return data, nil

	case nethttp.StatusTooManyRequests:
		retryAfter := resp.Header.Get("Retry-After")
		if retryAfter == "" {
			retryAfter = "a few minutes"
		}
		return nil, fmt.Errorf("rate limit exceeded (429). Retry after %s", retryAfter)

	default:
		return nil, fmt.Errorf(
			"unexpected API status: %d %s",
			resp.StatusCode,
			nethttp.StatusText(resp.StatusCode),
		)
	}
}

func handleFetchError(err error) {
	switch {
	case strings.Contains(err.Error(), "429"):
		logger.DefaultLogger.Warning(
			"Wordfence API rate limit hit (429). Please wait before retrying.",
		)
	default:
		logger.DefaultLogger.Error("Failed to retrieve Wordfence data: " + err.Error())
	}
}

func processWordfenceData(wfData map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, vulnData := range wfData {
		vulnMap, ok := vulnData.(map[string]interface{})
		if !ok {
			continue
		}

		title, _ := vulnMap["title"].(string)
		authType := ""

		var cvssScore float64
		var cvssVector, cvssRating string
		if cvss, ok := vulnMap["cvss"].(map[string]interface{}); ok {
			if score, exists := cvss["score"].(float64); exists {
				cvssScore = score
			}
			if vector, exists := cvss["vector"].(string); exists {
				cvssVector = vector
			}
			if rating, exists := cvss["rating"].(string); exists {
				cvssRating = strings.ToLower(rating)
			}
		}

		authType = vulnerability.DetermineAuthType(cvssVector, title)

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
					Severity:        cvssRating,
					CVE:             cve,
					CVELink:         cveLink,
					AuthType:        authType,
					CVSSScore:       cvssScore,
					CVSSVector:      cvssVector,
				}

				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}
