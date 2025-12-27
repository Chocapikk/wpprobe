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

package wpprobe_test

import (
	"context"
	"fmt"
	"log"
	"time"

	wpprobe "github.com/Chocapikk/wpprobe/pkg"
)

// ExampleScanner_Scan demonstrates a basic WordPress scan.
func ExampleScanner_Scan() {
	// Initialize the scanner
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	// Configure the scan
	cfg := wpprobe.Config{
		Target:       "https://example.com",
		ScanMode:     "stealthy", // Options: "stealthy", "bruteforce", "hybrid"
		Threads:      10,         // Number of concurrent threads
		RateLimit:    5,          // Requests per second (0 = unlimited)
		MaxRedirects: 10,         // Maximum redirects to follow (0 = disable, -1 = default: 10)
		Context:      context.Background(),
	}

	// Perform the scan
	result, err := scanner.Scan(cfg)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Display results
	fmt.Printf("Scan completed for: %s\n", result.Target)
	fmt.Printf("Plugins detected: %d\n", len(result.Plugins))
	fmt.Printf("Total vulnerabilities: %d\n", result.TotalVulnerabilities)
	fmt.Printf("Severity breakdown: Critical=%d, High=%d, Medium=%d, Low=%d\n",
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
	)

	// Iterate over detected plugins
	for _, plugin := range result.Plugins {
		fmt.Printf("\nPlugin: %s (v%s)\n", plugin.Name, plugin.Version)
		if len(plugin.Vulnerabilities.Critical) > 0 {
			fmt.Printf("  Critical: %d\n", len(plugin.Vulnerabilities.Critical))
		}
		if len(plugin.Vulnerabilities.High) > 0 {
			fmt.Printf("  High: %d\n", len(plugin.Vulnerabilities.High))
		}
		if len(plugin.Vulnerabilities.Medium) > 0 {
			fmt.Printf("  Medium: %d\n", len(plugin.Vulnerabilities.Medium))
		}
		if len(plugin.Vulnerabilities.Low) > 0 {
			fmt.Printf("  Low: %d\n", len(plugin.Vulnerabilities.Low))
		}
	}
}

// ExampleScanner_Scan_withTimeout demonstrates scanning with a timeout.
func ExampleScanner_Scan_withTimeout() {
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	// Create a context with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := wpprobe.Config{
		Target:   "https://example.com",
		ScanMode: "stealthy",
		Threads:  5,
		Context:  ctx,
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		if err == context.DeadlineExceeded {
			log.Println("Scan timed out")
		} else {
			log.Fatalf("Scan failed: %v", err)
		}
		return
	}

	fmt.Printf("Scan completed: %d plugins found\n", len(result.Plugins))
}

// ExampleScanner_Scan_withProgress demonstrates scanning with progress tracking.
func ExampleScanner_Scan_withProgress() {
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	cfg := wpprobe.Config{
		Target:   "https://example.com",
		ScanMode: "stealthy",
		Threads:  10,
		ProgressCallback: func(message string, current, total int) {
			// This callback is invoked during the scan to report progress
			fmt.Printf("[%d/%d] %s\n", current, total, message)
		},
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("Scan completed: %d plugins found\n", len(result.Plugins))
}

// ExampleScanner_Scan_withCustomHeaders demonstrates scanning with custom HTTP headers.
func ExampleScanner_Scan_withCustomHeaders() {
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	cfg := wpprobe.Config{
		Target:   "https://example.com",
		ScanMode: "stealthy",
		Threads:  10,
		Headers: []string{
			"User-Agent: CustomScanner/1.0",
			"X-Custom-Header: value",
		},
		Context: context.Background(),
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("Scan completed: %d plugins found\n", len(result.Plugins))
}

// ExampleScanner_Scan_withProxy demonstrates scanning through a proxy.
func ExampleScanner_Scan_withProxy() {
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	cfg := wpprobe.Config{
		Target:   "https://example.com",
		ScanMode: "stealthy",
		Threads:  10,
		Proxy:    "http://proxy.example.com:8080", // Proxy URL
		Context:  context.Background(),
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("Scan completed: %d plugins found\n", len(result.Plugins))
}

// ExampleScanner_Scan_filterResults demonstrates how to filter and process scan results.
func ExampleScanner_Scan_filterResults() {
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	cfg := wpprobe.Config{
		Target:   "https://example.com",
		ScanMode: "stealthy",
		Context:  context.Background(),
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Filter plugins with critical vulnerabilities
	var criticalPlugins []wpprobe.PluginResult
	for _, plugin := range result.Plugins {
		if len(plugin.Vulnerabilities.Critical) > 0 {
			criticalPlugins = append(criticalPlugins, plugin)
		}
	}

	fmt.Printf("Total plugins: %d\n", len(result.Plugins))
	fmt.Printf("Plugins with critical vulnerabilities: %d\n", len(criticalPlugins))

	// Display critical CVEs
	for _, plugin := range criticalPlugins {
		fmt.Printf("\n%s (v%s) - Critical CVEs:\n", plugin.Name, plugin.Version)
		for _, vuln := range plugin.Vulnerabilities.Critical {
			fmt.Printf("  - %s: %s\n", vuln.CVE, vuln.Title)
		}
	}
}

// ExampleScanner_Scan_bruteforceMode demonstrates using bruteforce scan mode.
func ExampleScanner_Scan_bruteforceMode() {
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	cfg := wpprobe.Config{
		Target:     "https://example.com",
		ScanMode:   "bruteforce",  // Brute-force mode checks thousands of plugins
		Threads:    20,            // Higher thread count for faster bruteforce
		RateLimit:  10,            // Limit rate to avoid overwhelming the server
		PluginList: "plugins.txt", // Path to plugin list file
		Context:    context.Background(),
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("Bruteforce scan completed: %d plugins found\n", len(result.Plugins))
}

// ExampleScanner_Scan_hybridMode demonstrates using hybrid scan mode.
func ExampleScanner_Scan_hybridMode() {
	scanner, err := wpprobe.New()
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	cfg := wpprobe.Config{
		Target:     "https://example.com",
		ScanMode:   "hybrid", // Hybrid mode: stealthy first, then bruteforce
		Threads:    15,
		RateLimit:  5,
		PluginList: "plugins.txt",
		Context:    context.Background(),
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("Hybrid scan completed: %d plugins found\n", len(result.Plugins))
}
