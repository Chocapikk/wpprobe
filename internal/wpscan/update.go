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

package wpscan

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"os"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/vulnerability"
)

const (
	wpscanAPIBase      = "https://wpscan.com/wp-json/api/v3"
	enterpriseDataBase = "https://enterprise-data.wpscan.com"
	httpTimeoutShort   = 15 * time.Second
	httpTimeoutLong    = 300 * time.Second
)

type Vulnerability = vulnerability.Vulnerability

type PlanInfo struct {
	Plan              string `json:"plan"`
	RequestsLimit     int    `json:"requests_limit"`
	RequestsRemaining int    `json:"requests_remaining"`
	RequestsReset     int64  `json:"requests_reset"`
}

func UpdateWPScan() error {
	apiToken := getAPIToken()
	if apiToken == "" {
		logger.DefaultLogger.Warning("WPSCAN_API_TOKEN not set, skipping WPScan update")
		return nil
	}

	logger.DefaultLogger.Info("Checking WPScan API plan...")
	planInfo, err := checkAPIPlan(apiToken)
	if err != nil {
		logger.DefaultLogger.Warning("Failed to check API plan: " + err.Error())
		logger.DefaultLogger.Warning("WPScan update requires Enterprise plan.")
		logger.DefaultLogger.Info("Skipping WPScan update. You can still use Wordfence database.")
		return nil
	}

	logger.DefaultLogger.Info(fmt.Sprintf("Plan: %s (Limit: %d, Remaining: %d)", planInfo.Plan, planInfo.RequestsLimit, planInfo.RequestsRemaining))

	if planInfo.Plan == "enterprise" {
		logger.DefaultLogger.Info("Using Enterprise database exports for complete data retrieval...")
		return updateWPScanEnterprise(apiToken)
	}

	planName := cases.Title(language.Und).String(planInfo.Plan)
	logger.DefaultLogger.Error(fmt.Sprintf("%s plan detected - WPScan database update requires Enterprise plan", planName))
	logger.DefaultLogger.Error("WPScan database update is only available with Enterprise plan.")
	logger.DefaultLogger.Error("Enterprise plan allows downloading complete database exports (10000+ plugins) in a single request.")
	logger.DefaultLogger.Warning("Skipping WPScan update. Upgrade to Enterprise plan for WPScan support.")
	logger.DefaultLogger.Info("You can still use Wordfence database (free and unlimited).")
	return nil
}

func getAPIToken() string {
	return os.Getenv("WPSCAN_API_TOKEN")
}

func checkAPIPlan(apiToken string) (*PlanInfo, error) {
	url := fmt.Sprintf("%s/status", wpscanAPIBase)
	var planInfo PlanInfo
	if err := makeAPIRequest(url, "Authorization", fmt.Sprintf("Token token=%s", apiToken), httpTimeoutShort, &planInfo); err != nil {
		return nil, err
	}
	return &planInfo, nil
}

func updateWPScanEnterprise(apiToken string) error {
	logger.DefaultLogger.Info("Downloading Enterprise database exports...")
	logger.DefaultLogger.Info("Downloading plugins database...")

	pluginsData, err := downloadEnterpriseExport("plugins.json.gz", apiToken)
	if err != nil {
		return fmt.Errorf("failed to download plugins database: %w", err)
	}

	allVulnerabilities := processPluginsData(pluginsData)
	logger.DefaultLogger.Info(fmt.Sprintf("Found %d plugin vulnerabilities from Enterprise database", len(allVulnerabilities)))

	logger.DefaultLogger.Info("Saving vulnerabilities to file...")
	if err := vulnerability.SaveVulnerabilitiesToFile(allVulnerabilities, "wpscan_vulnerabilities.json", "WPScan"); err != nil {
		return err
	}

	logger.DefaultLogger.Success("WPScan Enterprise data updated successfully!")
	return nil
}

func processPluginsData(pluginsData map[string]interface{}) []Vulnerability {
	var allVulnerabilities []Vulnerability
	for pluginSlug, pluginData := range pluginsData {
		if pluginMap, ok := pluginData.(map[string]interface{}); ok {
			vulns, err := processWPScanPluginData(pluginSlug, map[string]interface{}{pluginSlug: pluginMap})
			if err == nil {
				allVulnerabilities = append(allVulnerabilities, vulns...)
			}
		}
	}
	return allVulnerabilities
}

func downloadEnterpriseExport(filename string, apiToken string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/%s", enterpriseDataBase, filename)
	req, err := nethttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-DB-JSON-AUTH", apiToken)

	client := &nethttp.Client{Timeout: httpTimeoutLong}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != nethttp.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	data, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("JSON decoding error: %w", err)
	}

	return result, nil
}

func makeAPIRequest(url, headerName, headerValue string, timeout time.Duration, result interface{}) error {
	req, err := nethttp.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(headerName, headerValue)

	client := &nethttp.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != nethttp.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("JSON decoding error: %w", err)
	}

	return nil
}

func fetchPluginVulnerabilities(pluginSlug, apiToken string) ([]Vulnerability, error) {
	url := fmt.Sprintf("%s/plugins/%s", wpscanAPIBase, pluginSlug)
	var data map[string]interface{}
	if err := makeAPIRequest(url, "Authorization", fmt.Sprintf("Token token=%s", apiToken), httpTimeoutShort, &data); err != nil {
		if err.Error() == fmt.Sprintf("unexpected status: %d", nethttp.StatusNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return processWPScanPluginData(pluginSlug, data)
}

func processWPScanPluginData(pluginSlug string, data map[string]interface{}) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	pluginData, ok := data[pluginSlug].(map[string]interface{})
	if !ok {
		return vulnerabilities, nil
	}

	vulnsList, ok := pluginData["vulnerabilities"].([]interface{})
	if !ok {
		return vulnerabilities, nil
	}

	for _, vulnRaw := range vulnsList {
		vulnMap, ok := vulnRaw.(map[string]interface{})
		if !ok {
			continue
		}

		title, _ := vulnMap["title"].(string)
		if title == "" {
			continue
		}

		cve := extractCVE(vulnMap)
		fixedIn, _ := vulnMap["fixed_in"].(string)
		introducedIn, _ := vulnMap["introduced_in"].(string)
		fromVersion, toVersion, fromInclusive, toInclusive := determineVersionRange(introducedIn, fixedIn)
		cvssScore, cvssVector := extractCVSS(vulnMap)
		severity := determineSeverity(cvssScore, title)
		authType := determineAuthType(cvssVector, title)
		cveLink := vulnerability.BuildCVELink(cve)
		versionLabel := fmt.Sprintf("%s - %s", fromVersion, toVersion)

		vuln := Vulnerability{
			Title:           title,
			Slug:            pluginSlug,
			SoftwareType:    "plugin",
			AffectedVersion: versionLabel,
			FromVersion:     fromVersion,
			FromInclusive:   fromInclusive,
			ToVersion:       toVersion,
			ToInclusive:     toInclusive,
			Severity:        severity,
			CVE:             cve,
			CVELink:         cveLink,
			AuthType:        authType,
			CVSSScore:       cvssScore,
			CVSSVector:      cvssVector,
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

func extractCVE(vulnMap map[string]interface{}) string {
	refs, ok := vulnMap["references"].(map[string]interface{})
	if !ok {
		return ""
	}
	cves, ok := refs["cve"].([]interface{})
	if !ok || len(cves) == 0 {
		return ""
	}
	cveStr, ok := cves[0].(string)
	if !ok {
		return ""
	}
	return "CVE-" + cveStr
}

func determineVersionRange(introducedIn, fixedIn string) (string, string, bool, bool) {
	fromVersion := "0.0.0"
	toVersion := "999999.0.0"
	fromInclusive := true
	toInclusive := false

	if introducedIn != "" && introducedIn != "null" {
		fromVersion = introducedIn
	}
	if fixedIn != "" && fixedIn != "null" {
		toVersion = fixedIn
	}

	return fromVersion, toVersion, fromInclusive, toInclusive
}

func extractCVSS(vulnMap map[string]interface{}) (float64, string) {
	var cvssScore float64
	var cvssVector string
	cvss, ok := vulnMap["cvss"].(map[string]interface{})
	if !ok {
		return cvssScore, cvssVector
	}
	if score, ok := cvss["score"].(float64); ok {
		cvssScore = score
	}
	if vector, ok := cvss["vector"].(string); ok {
		cvssVector = vector
	}
	return cvssScore, cvssVector
}

func determineSeverity(cvssScore float64, title string) string {
	severity := vulnerability.DetermineSeverityFromCVSS(cvssScore)
	if severity == "unknown" {
		severity = vulnerability.DetermineSeverityFromTitle(title)
	}
	return severity
}

func determineAuthType(cvssVector string, title string) string {
	authType := vulnerability.DetermineAuthTypeFromCVSS(cvssVector)
	if authType == "" {
		authType = vulnerability.DetermineAuthTypeFromTitle(title)
	}
	return authType
}
