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

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/spf13/cobra"
)

func getProxyFromEnv() (string, string) {
	if v := firstNonEmpty(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")); v != "" {
		return v, "HTTPS_PROXY"
	}
	if v := firstNonEmpty(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy")); v != "" {
		return v, "HTTP_PROXY"
	}
	if v := firstNonEmpty(os.Getenv("ALL_PROXY"), os.Getenv("all_proxy")); v != "" {
		return v, "ALL_PROXY"
	}
	return "", ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a WordPress site for installed plugins and vulnerabilities",
	Long:  `Scans a WordPress site to detect installed plugins and check for known vulnerabilities using the Wordfence database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Configure logger verbosity first
		verbose := mustBool(cmd.Flags().GetBool("verbose"))
		logger.DefaultLogger.Verbose = verbose

		outputFile := cmd.Flag("output").Value.String()
		outputFormat := file.DetectOutputFormat(outputFile)

		headers, _ := cmd.Flags().GetStringArray("header")

		proxyURL := cmd.Flag("proxy").Value.String()

		if strings.TrimSpace(proxyURL) != "" {
			logger.DefaultLogger.Info("Using given proxy: " + proxyURL)
		} else {
			logger.DefaultLogger.Info("No proxy URL provided, checking environment variables")
			if envProxy, from := getProxyFromEnv(); envProxy != "" {
				proxyURL = envProxy
				logger.DefaultLogger.Info("Using proxy from " + from + ": " + proxyURL)
			} else {
				noProxy := firstNonEmpty(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
				if noProxy != "" {
					logger.DefaultLogger.Info("No explicit proxy; NO_PROXY is set: " + noProxy)
				} else {
					logger.DefaultLogger.Info("No proxy configured; using direct connection")
				}
			}
		}

		rateLimit := mustInt(cmd.Flags().GetInt("rate-limit"))

		opts := scanner.ScanOptions{
			URL:            cmd.Flag("url").Value.String(),
			File:           cmd.Flag("file").Value.String(),
			NoCheckVersion: mustBool(cmd.Flags().GetBool("no-check-version")),
			Threads:        mustInt(cmd.Flags().GetInt("threads")),
			Output:         outputFile,
			OutputFormat:   outputFormat,
			Verbose:        mustBool(cmd.Flags().GetBool("verbose")),
			ScanMode:       cmd.Flag("mode").Value.String(),
			PluginList:     cmd.Flag("plugin-list").Value.String(),
			Headers:        headers,
			Proxy:          proxyURL,
			RateLimit:      rateLimit,
		}

		if opts.URL == "" && opts.File == "" {
			return fmt.Errorf("you must provide either --url or --file")
		}

		scanner.ScanTargets(opts)
		return nil
	},
}

func init() {
	scanCmd.Flags().StringP("url", "u", "", "Target URL to scan")
	scanCmd.Flags().StringP("file", "f", "", "File containing a list of URLs")
	scanCmd.Flags().Bool("no-check-version", false, "Skip plugin version checking")
	scanCmd.Flags().IntP("threads", "t", 10, "Number of concurrent threads")
	scanCmd.Flags().StringP("output", "o", "", "Output file to save results (csv, json)")
	scanCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().StringP("mode", "m", "stealthy", "Scan mode: stealthy, bruteforce, or hybrid")
	scanCmd.Flags().
		StringP("plugin-list", "p", "", "Path to a custom plugin list file for bruteforce mode")
	scanCmd.Flags().
		StringArrayP("header", "H", []string{}, "HTTP header to include in requests. Can be specified multiple times.")
	scanCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy URL (e.g., http://127.0.0.1:8080)")
	scanCmd.Flags().
		Int("rate-limit", 0, "Maximum requests per second (0 = unlimited). Use to avoid overwhelming targets.")
}

func mustBool(value bool, err error) bool {
	if err != nil {
		logger.DefaultLogger.Warning("Failed to parse boolean flag, defaulting to false")
		return false
	}
	return value
}

func mustInt(value int, err error) int {
	if err != nil {
		logger.DefaultLogger.Warning("Failed to parse integer flag, defaulting to 10")
		return 10
	}
	return value
}
