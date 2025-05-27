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
	"os"

	"github.com/Chocapikk/wpprobe/internal/scanner"
	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a WordPress site for installed plugins and vulnerabilities",
	Long:  `Scans a WordPress site to detect installed plugins and check for known vulnerabilities using the Wordfence database.`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFile := cmd.Flag("output").Value.String()
		outputFormat := utils.DetectOutputFormat(outputFile)

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
		}

		if opts.URL == "" && opts.File == "" {
			utils.DefaultLogger.Error("You must provide either --url or --file")
			os.Exit(1)
		}

		scanner.ScanTargets(opts)
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
}

func mustBool(value bool, err error) bool {
	if err != nil {
		utils.DefaultLogger.Warning("Failed to parse boolean flag, defaulting to false")
		return false
	}
	return value
}

func mustInt(value int, err error) int {
	if err != nil {
		utils.DefaultLogger.Warning("Failed to parse integer flag, defaulting to 10")
		return 10
	}
	return value
}
