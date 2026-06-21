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
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Chocapikk/wpprobe/internal/file"
)

var (
	cachedDefaultPlugins     []string
	cachedDefaultPluginsOnce sync.Once
	cachedDefaultPluginsErr  error

	cachedFingerprints     map[string][]string
	cachedFingerprintSlugs []string
	cachedFingerprintsOnce sync.Once
	cachedFingerprintsErr  error
)

// LoadPluginFingerprints loads the per-plugin file fingerprint wordlist
// (files/plugin_fingerprints.txt). Each line is a relative path of the form
// "slug/file" (e.g. "woocommerce/woocommerce.php", "woocommerce/readme.txt").
// Lines are grouped by slug into an ordered list of candidate files, with the
// priority order from the wordlist preserved. The bruteforce scanner probes
// these files and treats a 200 response as a confirmed hit (see issue #27).
// The result is cached globally since the embedded list never changes.
func LoadPluginFingerprints() (map[string][]string, error) {
	cachedFingerprintsOnce.Do(func() {
		data, err := file.GetEmbeddedFile("files/plugin_fingerprints.txt")
		if err != nil {
			cachedFingerprintsErr = fmt.Errorf("failed to load plugin fingerprints: %w", err)
			return
		}
		fingerprints := make(map[string][]string, 8000)
		slugs := make([]string, 0, 8000)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			idx := strings.IndexByte(line, '/')
			if idx <= 0 || idx == len(line)-1 {
				continue
			}
			slug, relFile := line[:idx], line[idx+1:]
			if _, ok := fingerprints[slug]; !ok {
				slugs = append(slugs, slug)
			}
			fingerprints[slug] = append(fingerprints[slug], relFile)
		}
		cachedFingerprints = fingerprints
		cachedFingerprintSlugs = slugs
	})
	return cachedFingerprints, cachedFingerprintsErr
}

// LoadPluginsFromFile loads a list of plugins from an embedded file or a user-specified file.
// The default embedded plugin list is cached globally since it never changes.
func LoadPluginsFromFile(filename string) ([]string, error) {
	if filename == "" {
		cachedDefaultPluginsOnce.Do(func() {
			data, err := file.GetEmbeddedFile("files/wordpress_plugins.txt")
			if err != nil {
				cachedDefaultPluginsErr = fmt.Errorf("failed to load default plugin list: %w", err)
				return
			}
			scanner := bufio.NewScanner(bytes.NewReader(data))
			plugins := make([]string, 0, 10000)
			seen := make(map[string]struct{}, 10000)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				if _, ok := seen[line]; !ok {
					seen[line] = struct{}{}
					plugins = append(plugins, line)
				}
			}
			// Union with fingerprint slugs so plugins that ship a reliable file
			// signature but are missing from the popularity list are still probed.
			if _, fpErr := LoadPluginFingerprints(); fpErr == nil {
				for _, slug := range cachedFingerprintSlugs {
					if _, ok := seen[slug]; !ok {
						seen[slug] = struct{}{}
						plugins = append(plugins, slug)
					}
				}
			}
			cachedDefaultPlugins = plugins
		})
		return cachedDefaultPlugins, cachedDefaultPluginsErr
	}
	return file.ReadLines(filename)
}

// LoadPluginEndpointsFromData loads plugin endpoints from JSONL data.
func LoadPluginEndpointsFromData(data []byte) (map[string][]string, error) {
	lines := bytes.Split(data, []byte{'\n'})
	pluginEndpoints := make(map[string][]string, len(lines))

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var pluginData map[string][]string
		if err := json.Unmarshal(line, &pluginData); err != nil {
			continue
		}
		for plugin, endpoints := range pluginData {
			pluginEndpoints[plugin] = endpoints
		}
	}
	return pluginEndpoints, nil
}
