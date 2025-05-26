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
	if len(plugins) == 0 {
		utils.DefaultLogger.Warning("No plugins provided for brute-force scan")
		return []string{}
	}

	utils.DefaultLogger.Info(fmt.Sprintf("Starting brute-force scan with %d plugins", len(plugins)))

	var detected []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, threads)

	// Use the HTTP client manager from utils package with a 10-second timeout
	httpClient := utils.NewHTTPClient(10 * time.Second)
	// Normalize the target URL using the utility function
	normalizedURL := utils.NormalizeURL(target)

	// Initialize HTTP client and normalize URL

	for _, plugin := range plugins {
		wg.Add(1)
		sem <- struct{}{}
		
		go func(plugin string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					utils.DefaultLogger.Error(fmt.Sprintf("Panic occurred while scanning plugin %s: %v", plugin, r))
				}
			}()

			// Check for the plugin's readme.txt file instead of just the directory
			// This is more reliable for fingerprinting and consistent with stealthy mode
			url := fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", normalizedURL, plugin)
			
			// Implement retry mechanism for failed requests (up to 2 retries)
			const maxRetries = 2
			var err error
			
			for retry := 0; retry <= maxRetries; retry++ {
				// Use the HTTP client manager's Get method which handles User-Agent and other details
				_, err = httpClient.Get(url)
				
				// If successful or not a 404, break the retry loop
				if err == nil || !strings.Contains(err.Error(), "404") {
					break
				}
				
				// Only retry on network errors, not on 404s (which mean the plugin doesn't exist)
				if strings.Contains(err.Error(), "404") {
					break
				}
				
				if retry < maxRetries {
					// Exponential backoff: sleep 1s, then 2s before retrying
					time.Sleep(time.Duration(retry+1) * time.Second)
				}
			}
			
			// If we get a successful response or a non-404 error, the plugin likely exists
			if err == nil || !strings.Contains(err.Error(), "404") {
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
	
	utils.DefaultLogger.Info(fmt.Sprintf("Brute-force scan completed. Detected %d plugins.", len(detected)))
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
	utils.DefaultLogger.Info("Starting hybrid scan")
	utils.DefaultLogger.Info(fmt.Sprintf("Stealthy scan detected %d plugins", len(stealthyPlugins)))

	// For empty stealthy results, just run bruteforce directly
	if len(stealthyPlugins) == 0 {
		utils.DefaultLogger.Info("No plugins detected in stealthy scan, performing full brute-force scan")
		return BruteforcePlugins(target, bruteforcePlugins, threads, progress)
	}

	// Create a map of detected plugins from stealthy scan for quick lookup
	detectedMap := make(map[string]bool, len(stealthyPlugins))
	for _, plugin := range stealthyPlugins {
		detectedMap[plugin] = true
	}

	// Pre-allocate the remaining plugins slice to improve performance
	remainingPlugins := make([]string, 0, len(bruteforcePlugins))
	skippedCount := 0

	// Filter out plugins that were already found in stealthy scan
	for _, plugin := range bruteforcePlugins {
		if !detectedMap[plugin] {
			remainingPlugins = append(remainingPlugins, plugin)
		} else {
			skippedCount++
		}
	}

	utils.DefaultLogger.Info(fmt.Sprintf("Skipping %d plugins already found in stealthy scan", skippedCount))
	utils.DefaultLogger.Info(fmt.Sprintf("Continuing with brute-force scan for %d remaining plugins", len(remainingPlugins)))

	// Bruteforce remaining plugins
	bruteforceDetected := BruteforcePlugins(target, remainingPlugins, threads, progress)

	// Combine results - pre-allocate slice with exact size needed
	resultSize := len(stealthyPlugins) + len(bruteforceDetected)
	result := make([]string, len(stealthyPlugins), resultSize)
	copy(result, stealthyPlugins)
	result = append(result, bruteforceDetected...)

	utils.DefaultLogger.Info(fmt.Sprintf("Hybrid scan completed. Total detected plugins: %d", len(result)))
	return result
}
