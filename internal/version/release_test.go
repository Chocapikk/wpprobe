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
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// tagServer serves a tag list and counts how many times it was asked.
func tagServer(t *testing.T, requests *atomic.Int64, tags ...string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
			if requests != nil {
				requests.Add(1)
			}
			payload := make([]struct {
				Name string `json:"name"`
			}, 0, len(tags))
			for _, tag := range tags {
				payload = append(payload, struct {
					Name string `json:"name"`
				}{Name: tag})
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(payload); err != nil {
				t.Errorf("failed to encode tags: %v", err)
			}
		}),
	)
	t.Cleanup(server.Close)
	return server
}

// useTempCache points the cache at a directory this test owns, so a run never
// reads or writes the caller's real config directory.
func useTempCache(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "version_check.json")
	original := releaseCheckCachePath
	releaseCheckCachePath = func() (string, bool) { return path, true }
	t.Cleanup(func() { releaseCheckCachePath = original })
	return path
}

func useTagServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	original := tagsURL
	tagsURL = server.URL
	t.Cleanup(func() { tagsURL = original })
}

func TestCheckLatestVersion(t *testing.T) {
	tests := []struct {
		name        string
		current     string
		wantVersion string
		wantKnown   bool
		wantCurrent bool
	}{
		{"current is latest", "v1.2.0", "1.2.0", true, true},
		{"current is ahead", "v1.3.0", "1.2.0", true, true},
		{"current is outdated", "v1.0.0", "1.2.0", true, false},
		{"unparseable current version", "invalid", "1.2.0", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useTempCache(t)
			useTagServer(t, tagServer(t, nil, "v1.0.0", "v1.2.0", "v1.1.0"))

			got := CheckLatestVersion(tt.current)
			if got.Version != tt.wantVersion || got.Known != tt.wantKnown || got.Current != tt.wantCurrent {
				t.Errorf("CheckLatestVersion(%q) = %+v, want {Version:%q Known:%v Current:%v}",
					tt.current, got, tt.wantVersion, tt.wantKnown, tt.wantCurrent)
			}
		})
	}
}

// A lookup that fails must not be reported as "you are behind": that is what
// made an offline run claim the build was outdated and advise an update.
func TestCheckLatestVersionUnreachable(t *testing.T) {
	useTempCache(t)
	server := tagServer(t, nil, "v1.2.0")
	useTagServer(t, server)
	server.Close()

	got := CheckLatestVersion("v1.0.0")
	if got.Known {
		t.Errorf("CheckLatestVersion() = %+v, want Known false when the lookup fails", got)
	}
	if got.Current {
		t.Error("a failed lookup must not claim the build is current either")
	}
}

// The lookup runs on every invocation, so a second one within the TTL must be
// served from disk rather than from the network.
func TestCheckLatestVersionUsesCache(t *testing.T) {
	path := useTempCache(t)
	var requests atomic.Int64
	useTagServer(t, tagServer(t, &requests, "v1.2.0"))

	first := CheckLatestVersion("v1.0.0")
	second := CheckLatestVersion("v1.0.0")

	if requests.Load() != 1 {
		t.Errorf("tag endpoint hit %d times, want 1: the second check must reuse the cache", requests.Load())
	}
	if first != second {
		t.Errorf("cached answer %+v differs from the fetched one %+v", second, first)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected the lookup to be memoized at %s: %v", path, err)
	}
}

// Past the TTL the answer is fetched again, otherwise a released version would
// never be noticed.
func TestCheckLatestVersionRefetchesAfterTTL(t *testing.T) {
	path := useTempCache(t)
	var requests atomic.Int64
	useTagServer(t, tagServer(t, &requests, "v1.2.0"))

	stale, err := json.Marshal(releaseCheckCache{
		Latest:    "1.1.0",
		CheckedAt: time.Now().Add(-releaseCheckTTL - time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if err := os.WriteFile(path, stale, 0o644); err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	got := CheckLatestVersion("v1.0.0")
	if requests.Load() != 1 {
		t.Errorf("tag endpoint hit %d times, want 1: a stale cache must be refreshed", requests.Load())
	}
	if got.Version != "1.2.0" {
		t.Errorf("Version = %q, want the freshly fetched 1.2.0", got.Version)
	}
}

// The opt-out must stop the request from being made at all.
func TestCheckLatestVersionOptOut(t *testing.T) {
	useTempCache(t)
	var requests atomic.Int64
	useTagServer(t, tagServer(t, &requests, "v1.2.0"))
	t.Setenv(noCheckEnv, "1")

	got := CheckLatestVersion("v1.0.0")
	if requests.Load() != 0 {
		t.Errorf("tag endpoint hit %d times, want 0 when %s is set", requests.Load(), noCheckEnv)
	}
	if got.Known {
		t.Errorf("CheckLatestVersion() = %+v, want Known false when the check is disabled", got)
	}
}

// The banner and `wpprobe update` must not disagree inside one run, so the
// refresh path ignores the memo even while it is still fresh.
func TestRefreshLatestVersionIgnoresTheCache(t *testing.T) {
	path := useTempCache(t)
	var requests atomic.Int64
	useTagServer(t, tagServer(t, &requests, "v1.2.0"))

	fresh, err := json.Marshal(releaseCheckCache{Latest: "1.0.0", CheckedAt: time.Now()})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if err := os.WriteFile(path, fresh, 0o644); err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	cached := CheckLatestVersion("v1.1.0")
	if !cached.Current {
		t.Fatalf("precondition: the stale memo should make v1.1.0 look current, got %+v", cached)
	}
	if requests.Load() != 0 {
		t.Fatalf("the cached path made %d requests", requests.Load())
	}

	refreshed := RefreshLatestVersion("v1.1.0")
	if requests.Load() != 1 {
		t.Errorf("refresh made %d requests, want 1", requests.Load())
	}
	if refreshed.Version != "1.2.0" || refreshed.Current {
		t.Errorf("RefreshLatestVersion() = %+v, want the freshly fetched 1.2.0 and Current false", refreshed)
	}

	// And the refreshed answer replaces the memo, so the next run agrees.
	if again := CheckLatestVersion("v1.1.0"); again.Version != "1.2.0" || again.Current {
		t.Errorf("cached answer after refresh = %+v, want the refreshed 1.2.0", again)
	}
}

// A tag learned by the update command corrects the memo the banner reads.
func TestRememberLatestRelease(t *testing.T) {
	useTempCache(t)
	var requests atomic.Int64
	useTagServer(t, tagServer(t, &requests, "v1.0.0"))

	RememberLatestRelease("v1.2.0")

	got := CheckLatestVersion("v1.1.0")
	if requests.Load() != 0 {
		t.Errorf("the remembered tag should have been reused, %d requests went out", requests.Load())
	}
	if got.Version != "1.2.0" || got.Current {
		t.Errorf("CheckLatestVersion() = %+v, want the remembered 1.2.0 and Current false", got)
	}
}

// A tag that is not a version must not poison the memo.
func TestRememberLatestReleaseIgnoresGarbage(t *testing.T) {
	path := useTempCache(t)
	RememberLatestRelease("not-a-version")
	if _, err := os.Stat(path); err == nil {
		t.Error("an unparseable tag was written to the cache")
	}
}
