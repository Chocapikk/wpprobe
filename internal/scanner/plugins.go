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
)

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
		return nil, fmt.Errorf("❌ Error reading embedded JSONL data: %v", err)
	}

	return pluginEndpoints, nil
}

func DetectPlugins(detectedEndpoints []string, pluginEndpoints map[string][]string) (map[string]int, map[string]float64, map[string]bool, []string) {

	/*
	 🚧 Testing Phase: This solution is an improved compromise to balance detection accuracy
	 while minimizing false positives. It dynamically adjusts the detection threshold
	 to ensure we don't exclude plugins too aggressively.
	*/

	pluginScores := make(map[string]int)
	pluginConfidence := make(map[string]float64)
	pluginAmbiguity := make(map[string]bool)
	var detectedPlugins []string

	for plugin, knownRoutes := range pluginEndpoints {
		if len(knownRoutes) == 0 {
			continue
		}

		matchCount := 0
		for _, knownRoute := range knownRoutes {
			for _, endpoint := range detectedEndpoints {
				if endpoint == knownRoute {
					matchCount++
				}
			}
		}

		threshold := int(math.Max(1, float64(len(knownRoutes))*0.15))
		if matchCount >= threshold {
			pluginScores[plugin] = matchCount
			pluginConfidence[plugin] = (float64(matchCount) / float64(len(knownRoutes))) * 100
			detectedPlugins = append(detectedPlugins, plugin)
		}
	}

	ambiguousPlugins := make(map[string][]string)
	pluginEndpointsMap := make(map[string]string)

	for _, plugin := range detectedPlugins {
		endpointsKey := fmt.Sprintf("%v", pluginEndpoints[plugin])
		pluginEndpointsMap[plugin] = endpointsKey
		ambiguousPlugins[endpointsKey] = append(ambiguousPlugins[endpointsKey], plugin)
	}

	for _, plugins := range ambiguousPlugins {
		if len(plugins) > 1 {
			for _, plugin := range plugins {
				pluginAmbiguity[plugin] = true
			}
		}
	}

	return pluginScores, pluginConfidence, pluginAmbiguity, detectedPlugins
}
