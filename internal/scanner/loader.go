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

	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/logger"
)

// LoadPluginsFromFile loads a list of plugins from an embedded file or a user-specified file.
func LoadPluginsFromFile(filename string) ([]string, error) {
	if filename == "" {
		data, err := file.GetEmbeddedFile("files/wordpress_plugins.txt")
		if err != nil {
			return nil, fmt.Errorf("failed to load default plugin list: %w", err)
		}
		var plugins []string
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			if line := scanner.Text(); line != "" {
				plugins = append(plugins, line)
			}
		}
		return plugins, nil
	}
	return file.ReadLines(filename)
}

// LoadPluginEndpointsFromData loads plugin endpoints from JSONL data.
func LoadPluginEndpointsFromData(data []byte) (map[string][]string, error) {
	pluginEndpoints := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		var pluginData map[string][]string
		if err := json.Unmarshal(scanner.Bytes(), &pluginData); err != nil {
			continue
		}
		for plugin, endpoints := range pluginData {
			pluginEndpoints[plugin] = endpoints
		}
	}
	if err := scanner.Err(); err != nil {
		logger.DefaultLogger.Error("Error reading embedded JSONL data: " + err.Error())
		return nil, err
	}
	return pluginEndpoints, nil
}

