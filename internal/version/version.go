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

package version

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Chocapikk/wpprobe/internal/http"
	"github.com/Masterminds/semver"
)

var tagsURL = "https://api.github.com/repos/Chocapikk/wpprobe/tags"

var versionRegex = regexp.MustCompile(`(?:Stable tag|Version):\s*([0-9A-Za-z.\-]+)`)
var themeVersionRegex = regexp.MustCompile(`(?i)Version:\s*([0-9A-Za-z.\-]+)`)

var readmeNames = []string{"readme.txt", "Readme.txt", "README.txt"}

func CheckLatestVersion(currentVersion string) (string, bool) {
	resp, err := nethttp.Get(tagsURL)
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

func GetPluginVersion(target, plugin string, cfg http.Config) string {
	return GetPluginVersionWithContext(context.Background(), target, plugin, cfg)
}

func GetPluginVersionWithContext(ctx context.Context, target, plugin string, cfg http.Config) string {
	httpClient := cfg.NewClient(10 * time.Second)
	return fetchVersionFromReadme(ctx, httpClient, target, plugin)
}

// GetPluginVersionWithClient uses an existing HTTP client instead of creating a new one.
func GetPluginVersionWithClient(ctx context.Context, client *http.HTTPClientManager, target, plugin string) string {
	return fetchVersionFromReadme(ctx, client, target, plugin)
}

// CheckPluginExists checks if a plugin directory exists via GET request.
// Returns true if the server responds with 403 (directory exists but listing forbidden)
// or 200 with a directory listing containing readme.txt (avoids false positives from
// WordPress instances that return 200 for everything).
func CheckPluginExists(ctx context.Context, client *http.HTTPClientManager, target, plugin string) bool {
	url := target + "/wp-content/plugins/" + plugin + "/"
	status, body, err := client.GetStatusAndBody(ctx, url)
	if err != nil {
		return false
	}
	return status == 403 || (status == 200 && strings.Contains(strings.ToLower(body), "readme.txt"))
}

func fetchVersionFromReadme(ctx context.Context, client *http.HTTPClientManager, target, plugin string) string {
	base := target + "/wp-content/plugins/" + plugin + "/"
	for _, name := range readmeNames {
		select {
		case <-ctx.Done():
			return "unknown"
		default:
		}
		url := base + name
		if body, err := client.GetWithContext(ctx, url); err == nil {
			if m := versionRegex.FindStringSubmatch(body); len(m) > 1 {
				return strings.TrimSpace(m[1])
			}
		} else if ctx.Err() != nil {
			return "unknown"
		}
	}
	return "unknown"
}

// GetThemeVersionWithContext fetches the theme version from style.css.
// Only reads the first 8KB since the Version header is at the top of the file.
func GetThemeVersionWithContext(ctx context.Context, target, theme string, cfg http.Config) string {
	httpClient := cfg.NewClient(10 * time.Second)
	select {
	case <-ctx.Done():
		return "unknown"
	default:
	}
	url := target + "/wp-content/themes/" + theme + "/style.css"
	body, err := httpClient.GetPartialWithContext(ctx, url, 8192)
	if err != nil {
		return "unknown"
	}
	if m := themeVersionRegex.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return "unknown"
}

// semverCache avoids re-parsing the same version strings thousands of times
// during vulnerability matching. The vuln database has ~50K entries but many
// share the same from/to version strings.
var semverCache sync.Map

type semverCacheEntry struct {
	version *semver.Version
	ok      bool
}

func parseSemverCached(s string) (*semver.Version, bool) {
	if entry, ok := semverCache.Load(s); ok {
		e := entry.(semverCacheEntry)
		return e.version, e.ok
	}
	parsed, err := semver.NewVersion(s)
	if err != nil {
		semverCache.Store(s, semverCacheEntry{nil, false})
		return nil, false
	}
	semverCache.Store(s, semverCacheEntry{parsed, true})
	return parsed, true
}

func IsVersionVulnerable(version, fromVersion, toVersion string) bool {
	if version == "" || fromVersion == "" || toVersion == "" {
		return false
	}
	v, ok := parseSemverCached(version)
	if !ok {
		return false
	}
	f, ok := parseSemverCached(fromVersion)
	if !ok {
		return false
	}
	t, ok := parseSemverCached(toVersion)
	if !ok {
		return false
	}
	return v.Compare(f) >= 0 && v.Compare(t) <= 0
}
