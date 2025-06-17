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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
)

func TestGitHubLatestReleaseURL(t *testing.T) {
	expected := "https://api.github.com/repos/Chocapikk/wpprobe/releases/latest"
	if got := GitHubLatestReleaseURL(); got != expected {
		t.Errorf("GitHubLatestReleaseURL() = %v, want %v", got, expected)
	}
}

func TestGitHubDownloadURL(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		osName   string
		arch     string
		expected string
	}{
		{
			name:     "Linux amd64",
			version:  "v1.0.0",
			osName:   "linux",
			arch:     "amd64",
			expected: "https://github.com/Chocapikk/wpprobe/releases/download/v1.0.0/wpprobe_v1.0.0_linux_amd64",
		},
		{
			name:     "Windows amd64",
			version:  "v1.0.0",
			osName:   "windows",
			arch:     "amd64",
			expected: "https://github.com/Chocapikk/wpprobe/releases/download/v1.0.0/wpprobe_v1.0.0_windows_amd64.exe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GitHubDownloadURL(tt.version, tt.osName, tt.arch)
			if got != tt.expected {
				t.Errorf("GitHubDownloadURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func Test_getLatestVersion(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{"tag_name": "v1.2.3"}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("Failed to encode JSON response: %v", err)
		}
	}))
	defer mockServer.Close()

	originalFunc := GitHubLatestReleaseURL
	defer func() { GitHubLatestReleaseURL = originalFunc }()

	GitHubLatestReleaseURL = func() string { return mockServer.URL }

	got, err := getLatestVersion()
	if err != nil {
		t.Fatalf("getLatestVersion() error = %v", err)
	}
	if got != "v1.2.3" {
		t.Errorf("getLatestVersion() = %v, want %v", got, "v1.2.3")
	}
}

func Test_getLatestVersion_Error(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer mockServer.Close()

	originalFunc := GitHubLatestReleaseURL
	defer func() { GitHubLatestReleaseURL = originalFunc }()

	GitHubLatestReleaseURL = func() string { return mockServer.URL }

	_, err := getLatestVersion()
	if err == nil {
		t.Error("Expected error for invalid response, got nil")
	}
}

func TestAutoUpdate(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/Chocapikk/wpprobe/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]string{"tag_name": "v1.0.0"}); err != nil {
				t.Errorf("failed to encode JSON response: %v", err)
			}
		case "/download":
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("binary data")); err != nil {
				t.Errorf("failed to write binary data: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	originalGitHubLatest := GitHubLatestReleaseURL
	originalGitHubDownload := GitHubDownloadURL
	defer func() {
		GitHubLatestReleaseURL = originalGitHubLatest
		GitHubDownloadURL = originalGitHubDownload
	}()

	GitHubLatestReleaseURL = func() string {
		return mockServer.URL + "/repos/Chocapikk/wpprobe/releases/latest"
	}
	GitHubDownloadURL = func(version, os, arch string) string {
		return mockServer.URL + "/download"
	}

	exitCalled := false
	originalExit := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
	}
	defer func() { exitFunc = originalExit }()

	tmpFile, err := os.CreateTemp("", "wpprobe_test_*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if err := tmpFile.Close(); err != nil {
			t.Errorf("failed to close temp file: %v", err)
		}
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Errorf("failed to remove temp file: %v", err)
		}
	}()

	originalArg0 := os.Args[0]
	os.Args[0] = tmpFile.Name()
	defer func() { os.Args[0] = originalArg0 }()

	if err := AutoUpdate(Version); err != nil {
		t.Errorf("AutoUpdate() error = %v, want nil", err)
	}
	if !exitCalled {
		t.Error("expected exitFunc to be called, but it wasn't")
	}
}

func TestAutoUpdate_NotFound(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	originalFunc := GitHubLatestReleaseURL
	defer func() { GitHubLatestReleaseURL = originalFunc }()

	GitHubLatestReleaseURL = func() string { return mockServer.URL + "/repos/Chocapikk/wpprobe/releases/latest" }

	err := AutoUpdate(Version)
	if err == nil {
		t.Error("Expected error for 404, got nil")
	}
}

func Test_detectOS(t *testing.T) {
	if got := detectOS(); got != runtime.GOOS {
		t.Errorf("detectOS() = %v, want %v", got, runtime.GOOS)
	}
}

func Test_detectArch(t *testing.T) {
	if got := detectArch(); got != runtime.GOARCH {
		t.Errorf("detectArch() = %v, want %v", got, runtime.GOARCH)
	}
}
