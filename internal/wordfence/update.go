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
	"io"
	nethttp "net/http"
	"os"
	"strings"
	"time"

	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/vulnerability"
)

const (
	wordfenceAPI = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
	githubDBURL  = "https://github.com/Chocapikk/wpprobe/releases/download/db/wordfence_vulnerabilities.json"
)

// Vulnerability is an alias for the common vulnerability type.
type Vulnerability = vulnerability.Vulnerability

func getAPIKey() string {
	return os.Getenv("WORDFENCE_API_KEY")
}

func UpdateWordfence() error {
	apiKey := getAPIKey()
	if apiKey != "" {
		return updateFromAPI(apiKey)
	}

	logger.DefaultLogger.Info("No API key set, fetching from GitHub release...")
	return updateFromGitHub()
}

func updateFromAPI(apiKey string) error {
	logger.DefaultLogger.Info("Fetching Wordfence data...")

	data, err := fetchWordfenceData(apiKey)
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

func updateFromGitHub() error {
	client := &nethttp.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(githubDBURL)
	if err != nil {
		return fmt.Errorf("failed to download database from GitHub: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != nethttp.StatusOK {
		return fmt.Errorf("GitHub download failed: %d %s", resp.StatusCode, nethttp.StatusText(resp.StatusCode))
	}

	outputPath, err := file.GetStoragePath("wordfence_vulnerabilities.json")
	if err != nil {
		return err
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write database: %w", err)
	}

	logger.DefaultLogger.Success("Wordfence data downloaded from GitHub release.")
	return nil
}

func fetchWordfenceData(apiKey string) (map[string]interface{}, error) {
	req, err := nethttp.NewRequest("GET", wordfenceAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &nethttp.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
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
