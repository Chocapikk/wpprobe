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

package utils

import (
	"fmt"
	"github.com/Masterminds/semver"
	"regexp"
	"strings"
	"time"
)

func GetPluginVersion(target, plugin string) string {
	httpClient := NewHTTPClient(10 * time.Second)

	version := fetchVersionFromReadme(httpClient, target, plugin)
	if version == "" {
		version = fetchVersionFromStyle(httpClient, target, plugin)
	}
	if version == "" {
		return "unknown"
	}
	return version
}

func fetchVersionFromReadme(client *HTTPClientManager, target, plugin string) string {
	readmes := []string{"readme.txt", "Readme.txt", "README.txt"}
	var version string

	for _, readmeName := range readmes {
		url := fmt.Sprintf("%s/wp-content/plugins/%s/%s", target, plugin, readmeName)
		version = fetchVersionFromURL(client, url, `(?:Stable tag|Version):\s*([0-9a-zA-Z.-]+)`)
		if version != "" {
			break
		}
	}
	return version
}

func fetchVersionFromStyle(client *HTTPClientManager, target, plugin string) string {
	url := fmt.Sprintf("%s/wp-content/themes/%s/style.css", target, plugin)
	return fetchVersionFromURL(client, url, `Version:\s*([0-9a-zA-Z.-]+)`)
}

func fetchVersionFromURL(client *HTTPClientManager, url, pattern string) string {
	body, err := client.Get(url)
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func IsVersionVulnerable(version, fromVersion, toVersion string) bool {
	if version == "" || fromVersion == "" || toVersion == "" {
		return false
	}

	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	from, err := semver.NewVersion(fromVersion)
	if err != nil {
		return false
	}
	to, err := semver.NewVersion(toVersion)
	if err != nil {
		return false
	}

	return v.Compare(from) >= 0 && v.Compare(to) <= 0
}
