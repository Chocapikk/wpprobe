// Copyright (c) 2025 Yiğit İbrahim (ibrahimsql) <ibrahimsql@proton.me>
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

package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Chocapikk/wpprobe/internal/utils"
)

// LoadPluginsFromFile loads a list of plugins from a file for bruteforce scanning
func LoadPluginsFromFile(filename string) ([]string, error) {
	if filename == "" {
		// If no file is provided, load the default plugin list from embedded files
		data, err := utils.GetEmbeddedFile("files/wordpress_plugins.txt")
		if err != nil {
			return nil, fmt.Errorf("failed to load default plugin list: %v", err)
		}

		// Parse the file content line by line
		var plugins []string
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				plugins = append(plugins, line)
			}
		}
		return plugins, nil
	}

	// Load from user-provided file
	plugins, err := utils.ReadLines(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin list file: %v", err)
	}

	return plugins, nil
}

// BruteforcePlugins attempts to detect plugins by checking if they exist on the target site
func BruteforcePlugins(
	target string,
	plugins []string,
	threads int,
	progress *utils.ProgressManager,
) []string {
	var detected []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, threads)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, plugin := range plugins {
		wg.Add(1)
		sem <- struct{}{}

		go func(plugin string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = recover() }()

			// Normalize URL
			normalizedURL := target
			// Remove trailing slash if present
			normalizedURL = strings.TrimSuffix(normalizedURL, "/")
			// Ensure URL has http:// or https:// prefix
			if !strings.HasPrefix(normalizedURL, "http://") && !strings.HasPrefix(normalizedURL, "https://") {
				normalizedURL = "https://" + normalizedURL
			}

			url := fmt.Sprintf("%s/wp-content/plugins/%s/", normalizedURL, plugin)
			req, err := http.NewRequest("HEAD", url, nil)
			if err != nil {
				return
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Plugins typically return 200 OK or 403 Forbidden if they exist
			// 404 Not Found means the plugin doesn't exist
			if resp.StatusCode != 404 {
				mu.Lock()
				detected = append(detected, plugin)
				mu.Unlock()
			}

			if progress != nil {
				progress.Increment()
			}
		}(plugin)
	}

	wg.Wait()
	return detected
}

// HybridScan performs a hybrid scan that starts with stealthy mode and then skips already found plugins during bruteforce
func HybridScan(
	target string,
	stealthyPlugins []string,
	bruteforcePlugins []string,
	threads int,
	progress *utils.ProgressManager,
) []string {
	// Create a map of detected plugins from stealthy scan for quick lookup
	detectedMap := make(map[string]bool)
	for _, plugin := range stealthyPlugins {
		detectedMap[plugin] = true
	}

	// Filter out plugins that were already found in stealthy scan
	var remainingPlugins []string
	for _, plugin := range bruteforcePlugins {
		if !detectedMap[plugin] {
			remainingPlugins = append(remainingPlugins, plugin)
		}
	}

	// Bruteforce remaining plugins
	bruteforceDetected := BruteforcePlugins(target, remainingPlugins, threads, progress)

	// Combine results
	result := append([]string{}, stealthyPlugins...)
	result = append(result, bruteforceDetected...)

	return result
}
