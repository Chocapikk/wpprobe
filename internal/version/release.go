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
	"encoding/json"
	nethttp "net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Masterminds/semver"
)

var tagsURL = "https://api.github.com/repos/Chocapikk/wpprobe/tags"

// releaseCheckTimeout bounds the tag lookup. It runs before anything else the
// command was asked to do, so an unreachable or slow GitHub must not be able to
// hold the whole run up: the check is a courtesy, not a prerequisite.
const releaseCheckTimeout = 4 * time.Second

// releaseCheckTTL is how long a lookup is reused. It trades a request per
// invocation against how stale the banner can be, and the banner states a fact
// rather than a hint: an hour keeps the badge defensible while still collapsing
// a working session's many runs into a single lookup. A day did not - a build
// published three hours after the last check was still announced as current.
const releaseCheckTTL = time.Hour

// noCheckEnv disables the lookup entirely for people who would rather their
// scanner not talk to github.com on startup.
const noCheckEnv = "WPPROBE_NO_UPDATE_CHECK"

// Latest is what the release check could establish.
type Latest struct {
	// Version is the newest published release. Empty when Known is false.
	Version string
	// Known reports whether the lookup produced an answer at all. A failed
	// lookup used to be indistinguishable from "you are behind", so running
	// offline reported the build as outdated and advised an update.
	Known bool
	// Current reports whether the running build is at or ahead of Version. It
	// carries no meaning when Known is false.
	Current bool
}

// CheckLatestVersion compares currentVersion with the newest published tag,
// reusing a cached answer for releaseCheckTTL so the lookup does not run on
// every invocation.
func CheckLatestVersion(currentVersion string) Latest {
	return checkLatestVersion(currentVersion, false)
}

// RefreshLatestVersion is CheckLatestVersion without the cached shortcut, for
// the moments where the answer has to be current rather than recent: `wpprobe
// update` is about to act on it, and a banner contradicting the command running
// underneath it is worse than a request.
func RefreshLatestVersion(currentVersion string) Latest {
	return checkLatestVersion(currentVersion, true)
}

func checkLatestVersion(currentVersion string, refresh bool) Latest {
	if os.Getenv(noCheckEnv) != "" {
		return Latest{}
	}

	latestVersion, ok := "", false
	if !refresh {
		latestVersion, ok = cachedLatestTag()
	}
	if !ok {
		if latestVersion, ok = fetchLatestTag(); !ok {
			return Latest{}
		}
		storeLatestTag(latestVersion)
	}

	latest, err := semver.NewVersion(latestVersion)
	if err != nil {
		return Latest{}
	}
	current, err := semver.NewVersion(trimVersionPrefix(currentVersion))
	if err != nil {
		return Latest{Version: latest.String(), Known: true}
	}
	return Latest{Version: latest.String(), Known: true, Current: current.Compare(latest) >= 0}
}

func trimVersionPrefix(version string) string {
	if len(version) > 0 && (version[0] == 'v' || version[0] == 'V') {
		return version[1:]
	}
	return version
}

// fetchLatestTag returns the highest semver tag the repository publishes.
func fetchLatestTag() (string, bool) {
	client := &nethttp.Client{Timeout: releaseCheckTimeout}
	resp, err := client.Get(tagsURL)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()

	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", false
	}

	var highest *semver.Version
	for _, tag := range tags {
		parsed, err := semver.NewVersion(trimVersionPrefix(tag.Name))
		if err != nil {
			continue
		}
		if highest == nil || parsed.Compare(highest) > 0 {
			highest = parsed
		}
	}
	if highest == nil {
		return "", false
	}
	return highest.String(), true
}

// releaseCheckCache is the on-disk memo of the last successful lookup.
type releaseCheckCache struct {
	Latest    string    `json:"latest"`
	CheckedAt time.Time `json:"checked_at"`
}

// releaseCheckCachePath is a variable so tests can redirect it away from the
// user's real config directory.
var releaseCheckCachePath = func() (string, bool) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(configDir, "wpprobe", "version_check.json"), true
}

// cachedLatestTag returns the memoized tag while it is younger than
// releaseCheckTTL. Every failure is silent: a cache that cannot be read is a
// missing optimisation, not something worth interrupting the run for.
func cachedLatestTag() (string, bool) {
	path, ok := releaseCheckCachePath()
	if !ok {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var cache releaseCheckCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return "", false
	}
	if cache.Latest == "" || time.Since(cache.CheckedAt) > releaseCheckTTL {
		return "", false
	}
	return cache.Latest, true
}

// RememberLatestRelease records a release tag learned elsewhere, so a lookup the
// update command already paid for corrects the banner instead of leaving it to
// contradict what the user was just told. The tag is normalized to match what
// fetchLatestTag stores.
func RememberLatestRelease(tag string) {
	parsed, err := semver.NewVersion(trimVersionPrefix(tag))
	if err != nil {
		return
	}
	storeLatestTag(parsed.String())
}

// storeLatestTag memoizes a successful lookup, best effort.
func storeLatestTag(latest string) {
	path, ok := releaseCheckCachePath()
	if !ok {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	raw, err := json.Marshal(releaseCheckCache{Latest: latest, CheckedAt: time.Now()})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o644)
}
