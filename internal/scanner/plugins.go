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
	"math"

	"github.com/Chocapikk/wpprobe/internal/utils"
)

type PluginData struct {
	Score      int
	Confidence float64
	Ambiguous  bool
	Matches    []string
}

type PluginDetectionResult struct {
	Plugins  map[string]*PluginData
	Detected []string
}

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
		utils.DefaultLogger.Error("Error reading embedded JSONL data: " + err.Error())
		return nil, err
	}
	return pluginEndpoints, nil
}

func DetectPlugins(
	detectedEndpoints []string,
	pluginEndpoints map[string][]string,
) PluginDetectionResult {
	detection := PluginDetectionResult{
		Plugins: make(map[string]*PluginData),
	}

	for plugin, knownRoutes := range pluginEndpoints {
		if len(knownRoutes) == 0 {
			continue
		}
		var matchCount int
		for _, knownRoute := range knownRoutes {
			for _, endpoint := range detectedEndpoints {
				if endpoint == knownRoute {
					matchCount++
				}
			}
		}

		if matchCount > 0 {
			confidence := (float64(matchCount) / float64(len(knownRoutes))) * 100
			confidence = math.Round(confidence*100) / 100
			detection.Plugins[plugin] = &PluginData{
				Score:      matchCount,
				Confidence: confidence,
			}
			detection.Detected = append(detection.Detected, plugin)
		}
	}

	ambiguousGroups := make(map[string][]string)
	pluginEndpointsMap := make(map[string]string)
	for plugin := range detection.Plugins {
		key := fmt.Sprintf("%v", pluginEndpoints[plugin])
		pluginEndpointsMap[plugin] = key
		ambiguousGroups[key] = append(ambiguousGroups[key], plugin)
	}

	for _, group := range ambiguousGroups {
		if len(group) > 1 {
			for _, pl := range group {
				detection.Plugins[pl].Ambiguous = true
				detection.Plugins[pl].Matches = group
			}
		} else {
			for _, pl := range group {
				detection.Plugins[pl].Matches = []string{}
			}
		}
	}

	return detection
}
