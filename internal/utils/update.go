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
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
)

const githubRepo = "Chocapikk/wpprobe"

var exitFunc = os.Exit

var GitHubLatestReleaseURL = func() string {
	return fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
}

var GitHubDownloadURL = func(version, osName, arch string) string {
	var ext string
	if osName == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf(
		"https://github.com/%s/releases/download/%s/wpprobe_%s_%s_%s%s",
		githubRepo,
		version,
		version,
		osName,
		arch,
		ext,
	)
}

func getLatestVersion() (string, error) {
	DefaultLogger.Info("Fetching latest WPProbe version...")
	resp, err := http.Get(GitHubLatestReleaseURL())
	if err != nil {
		DefaultLogger.Error("Failed to fetch latest release: " + err.Error())
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		DefaultLogger.Error(fmt.Sprintf("GitHub API error: %d", resp.StatusCode))
		return "", fmt.Errorf("GitHub API error: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		DefaultLogger.Error("Failed to parse JSON response: " + err.Error())
		return "", err
	}

	version, ok := result["tag_name"].(string)
	if !ok || version == "" {
		DefaultLogger.Error("Failed to extract latest version from GitHub API")
		return "", fmt.Errorf("invalid version format")
	}

	DefaultLogger.Success("Latest WPProbe version found: " + version)
	return version, nil
}

func AutoUpdate() error {
	DefaultLogger.Info("Checking for WPProbe updates...")

	version, err := getLatestVersion()
	if err != nil {
		return err
	}

	osName := detectOS()
	arch := detectArch()
	updateURL := GitHubDownloadURL(version, osName, arch)

	DefaultLogger.Info("Downloading WPProbe update from: " + updateURL)
	resp, err := http.Get(updateURL)
	if err != nil {
		DefaultLogger.Error("Failed to download update: " + err.Error())
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		DefaultLogger.Error(fmt.Sprintf("Update not found: %s", updateURL))
		return fmt.Errorf("update not found at %s", updateURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		DefaultLogger.Error("Failed to read update response: " + err.Error())
		return err
	}

	currentExe, err := os.Executable()
	if err != nil {
		DefaultLogger.Error("Failed to determine executable path: " + err.Error())
		return err
	}

	DefaultLogger.Info("Replacing current binary: " + currentExe)
	tmpFile := currentExe + ".tmp"

	if err := os.WriteFile(tmpFile, body, 0o755); err != nil {
		DefaultLogger.Error("Failed to write temp file: " + err.Error())
		return err
	}

	if runtime.GOOS == "windows" {
		if err := os.Remove(currentExe); err != nil {
			DefaultLogger.Warning(
				"Failed removing current file (Windows lock issues?). " + err.Error(),
			)
		}
	}

	if err := os.Rename(tmpFile, currentExe); err != nil {
		DefaultLogger.Error("Failed to replace old binary: " + err.Error())
		return err
	}

	DefaultLogger.Success("Update successful! Restart WPProbe to use the new version.")
	exitFunc(0)
	return nil
}

func detectOS() string {
	return runtime.GOOS
}

func detectArch() string {
	return runtime.GOARCH
}
