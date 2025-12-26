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
	"math"
	"strings"
)

func buildEndpointsKey(endpoints []string) string {
	return strings.Join(endpoints, "|")
}

// DetectPlugins detects plugins by matching detected endpoints with known plugin endpoints.
func DetectPlugins(
	detectedEndpoints []string,
	pluginEndpoints map[string][]string,
) PluginDetectionResult {
	detection := PluginDetectionResult{
		Plugins: make(map[string]*PluginData),
	}

	// Build endpoint map for O(1) lookup instead of O(n) linear search
	endpointMap := make(map[string]bool, len(detectedEndpoints))
	for _, ep := range detectedEndpoints {
		endpointMap[ep] = true
	}

	for plugin, knownRoutes := range pluginEndpoints {
		if len(knownRoutes) == 0 {
			continue
		}
		var matchCount int
		for _, knownRoute := range knownRoutes {
			if endpointMap[knownRoute] {
				matchCount++
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

	// Mark ambiguous plugins (plugins that share the same endpoints)
	ambiguousGroups := make(map[string][]string)
	pluginEndpointsMap := make(map[string]string)
	for plugin := range detection.Plugins {
		endpoints := pluginEndpoints[plugin]
		key := buildEndpointsKey(endpoints)
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

