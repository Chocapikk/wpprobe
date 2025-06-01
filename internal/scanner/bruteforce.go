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

package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/Chocapikk/wpprobe/internal/utils"
)

// LoadPluginsFromFile loads a list of plugins from an embedded file or a user-specified file.
func LoadPluginsFromFile(filename string) ([]string, error) {
	if filename == "" {
		data, err := utils.GetEmbeddedFile("files/wordpress_plugins.txt")
		if err != nil {
			return nil, fmt.Errorf("failed to load default plugin list: %v", err)
		}
		var plugins []string
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				plugins = append(plugins, line)
			}
		}
		return plugins, nil
	}
	return utils.ReadLines(filename)
}

// BruteforcePlugins attempts to detect plugins by parsing their readme.txt for version.
// It updates the progress bar message with a fixed-width plugin name.
func BruteforcePlugins(
	target string,
	plugins []string,
	threads int,
	progress *utils.ProgressManager,
	headers []string,
) []string {
	if len(plugins) == 0 {
		utils.DefaultLogger.Warning("No plugins provided for brute-force scan")
		return nil
	}

	normalized := utils.NormalizeURL(target)
	var (
		detected []string
		wg       sync.WaitGroup
		mu       sync.Mutex
		sem      = make(chan struct{}, threads)
	)

	for _, plugin := range plugins {
		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					utils.DefaultLogger.Error(
						fmt.Sprintf("Panic while scanning plugin %s: %v", p, r),
					)
				}
			}()

			if progress != nil {
				progress.SetMessage(fmt.Sprintf("🔎 Bruteforcing plugin %-30.30s", p))
			}

			version := utils.GetPluginVersion(normalized, p, threads, headers)
			if version != "" && version != "unknown" {
				if progress != nil {
					progress.ClearLine()
				}
				utils.DefaultLogger.Info(fmt.Sprintf("Found plugin %s version %s", p, version))
				if progress != nil {
					progress.RenderBlank()
				}

				mu.Lock()
				detected = append(detected, p)
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

// HybridScan performs a hybrid scan: first stealthy, then brute-forces remaining plugins.
func HybridScan(
	target string,
	stealthyPlugins []string,
	bruteforcePlugins []string,
	threads int,
	progress *utils.ProgressManager,
	headers []string,
) []string {
	if len(stealthyPlugins) == 0 {
		return BruteforcePlugins(target, bruteforcePlugins, threads, progress, headers)
	}

	detectedMap := make(map[string]bool, len(stealthyPlugins))
	for _, p := range stealthyPlugins {
		detectedMap[p] = true
	}

	var remaining []string
	for _, p := range bruteforcePlugins {
		if !detectedMap[p] {
			remaining = append(remaining, p)
		}
	}

	brutefound := BruteforcePlugins(target, remaining, threads, progress, headers)
	result := make([]string, len(stealthyPlugins), len(stealthyPlugins)+len(brutefound))
	copy(result, stealthyPlugins)
	return append(result, brutefound...)
}
