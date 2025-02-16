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
	"os"

	"github.com/fynelabs/selfupdate"
	"github.com/goccy/go-json"
)

const githubRepo = "Chocapikk/wpprobe"

func GitHubLatestReleaseURL() string {
	return fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
}

func GitHubDownloadURL(version, os, arch string) string {
	return fmt.Sprintf(
		"https://github.com/%s/releases/download/%s/wpprobe-%s-%s",
		githubRepo,
		version,
		os,
		arch,
	)
}

func getLatestVersion() (string, error) {
	logger.Info("Fetching latest WPProbe version...")

	resp, err := http.Get(GitHubLatestReleaseURL())
	if err != nil {
		logger.Error("Failed to fetch latest release: " + err.Error())
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error(fmt.Sprintf("GitHub API error: %d", resp.StatusCode))
		return "", fmt.Errorf("GitHub API error: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Error("Failed to parse JSON response: " + err.Error())
		return "", err
	}

	version, ok := result["tag_name"].(string)
	if !ok || version == "" {
		logger.Error("Failed to extract latest version from GitHub API")
		return "", fmt.Errorf("invalid version format")
	}

	logger.Success("Latest WPProbe version found: " + version)
	return version, nil
}

func AutoUpdate() error {
	logger.Info("Checking for WPProbe updates...")

	version, err := getLatestVersion()
	if err != nil {
		return err
	}

	osName := detectOS()
	arch := detectArch()
	updateURL := GitHubDownloadURL(version, osName, arch)

	logger.Info("Downloading WPProbe update from: " + updateURL)

	resp, err := http.Get(updateURL)
	if err != nil {
		logger.Error("Failed to download update: " + err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error(fmt.Sprintf("Failed to download update, status: %d", resp.StatusCode))
		return fmt.Errorf("failed to download update, status: %d", resp.StatusCode)
	}

	executable, err := os.Executable()
	if err != nil {
		logger.Error("Failed to determine executable path: " + err.Error())
		return err
	}

	logger.Info("Replacing current binary: " + executable)

	err = selfupdate.Apply(resp.Body, selfupdate.Options{
		TargetPath: executable,
	})
	if err != nil {
		logger.Error("Failed to update WPProbe: " + err.Error())

		if rerr := selfupdate.RollbackError(err); rerr != nil {
			logger.Error("Failed to rollback after failed update: " + rerr.Error())
		} else {
			logger.Warning("Update failed but rollback was successful.")
		}
		return err
	}

	logger.Success("Update successful! Restart WPProbe to use the new version.")
	os.Exit(0)
	return nil
}

func detectOS() string {
	switch os := os.Getenv("GOOS"); os {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	default:
		return "linux"
	}
}

func detectArch() string {
	switch arch := os.Getenv("GOARCH"); arch {
	case "arm64":
		return "arm64"
	default:
		return "amd64"
	}
}
