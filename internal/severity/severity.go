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

package severity

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	// Order defines the order of severities from highest to lowest.
	Order = []string{"critical", "high", "medium", "low", "unknown"}

	titleCaser = cases.Title(language.Und, cases.NoLower)
)

// Normalize normalizes a severity string to lowercase and validates it.
func Normalize(sev string) string {
	sevLower := strings.ToLower(sev)
	if IndexOf(Order, sevLower) < len(Order) {
		return sevLower
	}
	return "unknown"
}

// IndexOf returns the index of a string in a slice, or the length of the slice if not found.
func IndexOf(arr []string, s string) int {
	for i, v := range arr {
		if v == s {
			return i
		}
	}
	return len(arr)
}

// InitializeCounts creates a new map with all severity counts initialized to 0.
func InitializeCounts() map[string]int {
	return map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"unknown":  0,
	}
}

// CountBySeverity counts vulnerabilities by their severity.
func CountBySeverity(severities []string) map[string]int {
	counts := InitializeCounts()
	for _, sev := range severities {
		normalized := Normalize(sev)
		counts[normalized]++
	}
	return counts
}

// FormatTitleCase formats a severity string in title case without styling.
func FormatTitleCase(sev string) string {
	return titleCaser.String(strings.ToLower(sev))
}

// NormalizeAuth normalizes an authentication type string.
func NormalizeAuth(auth string) string {
	authLower := strings.ToLower(auth)
	if authLower == "auth" || authLower == "unauth" || authLower == "privileged" {
		return authLower
	}
	return "unknown"
}
