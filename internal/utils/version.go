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
	"net/http"
	"regexp"
	"strings"
	"time"

	"encoding/json"

	"github.com/Masterminds/semver"
)

var tagsURL = "https://api.github.com/repos/Chocapikk/wpprobe/tags"

func CheckLatestVersion(currentVersion string) (string, bool) {
	resp, err := http.Get(tagsURL)
	if err != nil {
		return "unknown", false
	}
	defer func() { _ = resp.Body.Close() }()

	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "unknown", false
	}
	if len(tags) == 0 {
		return "unknown", false
	}

	var latest *semver.Version
	for _, tag := range tags {
		vstr := strings.TrimPrefix(tag.Name, "v")
		if v, err := semver.NewVersion(vstr); err == nil {
			if latest == nil || v.Compare(latest) > 0 {
				latest = v
			}
		}
	}
	if latest == nil {
		return "unknown", false
	}

	curr, err := semver.NewVersion(strings.TrimPrefix(currentVersion, "v"))
	if err != nil {
		return latest.String(), false
	}
	return latest.String(), curr.Compare(latest) >= 0
}

func GetPluginVersion(target, plugin string, _ int) string {
	httpClient := NewHTTPClient(10 * time.Second)
	return fetchVersionFromReadme(httpClient, target, plugin)
}

func fetchVersionFromReadme(client *HTTPClientManager, target, plugin string) string {
	readmes := []string{"readme.txt", "Readme.txt", "README.txt"}
	for _, name := range readmes {
		url := fmt.Sprintf("%s/wp-content/plugins/%s/%s", target, plugin, name)
		if body, err := client.Get(url); err == nil {
			re := regexp.MustCompile(`(?:Stable tag|Version):\s*([0-9A-Za-z.\-]+)`)
			if m := re.FindStringSubmatch(body); len(m) > 1 {
				return strings.TrimSpace(m[1])
			}
		}
	}
	return "unknown"
}

func IsVersionVulnerable(version, fromVersion, toVersion string) bool {
	if version == "" || fromVersion == "" || toVersion == "" {
		return false
	}
	v, err1 := semver.NewVersion(version)
	f, err2 := semver.NewVersion(fromVersion)
	t, err3 := semver.NewVersion(toVersion)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	return v.Compare(f) >= 0 && v.Compare(t) <= 0
}
