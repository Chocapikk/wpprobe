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

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/utils"
)

func createTempDirWithSubdir(t *testing.T) string {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}
	return subdir
}

func createTempFile(t *testing.T) string {
	tmpFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	return tmpFile.Name()
}

func Test_removeDir(t *testing.T) {
	logger := utils.NewLogger()
	subdir := createTempDirWithSubdir(t)
	if _, err := os.Stat(subdir); os.IsNotExist(err) {
		t.Fatalf("Subdir does not exist before removal")
	}
	removeDir(subdir, "Test subdir", logger)
	if _, err := os.Stat(subdir); !os.IsNotExist(err) {
		t.Errorf("Subdir was not removed")
	}
}

func Test_removeFile(t *testing.T) {
	logger := utils.NewLogger()
	tmpFile := createTempFile(t)
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatalf("Temp file does not exist before removal")
	}
	removeFile(tmpFile, "Test file", logger)
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Errorf("Temp file was not removed")
	}
}

func Test_mustGetUserConfigDir(t *testing.T) {
	logger := utils.NewLogger()
	configDir := mustGetUserConfigDir(logger)
	if configDir == "" {
		t.Errorf("mustGetUserConfigDir returned empty string")
	}
}

func Test_mustGetExecutable(t *testing.T) {
	logger := utils.NewLogger()
	execPath := mustGetExecutable(logger)
	if execPath == "" {
		t.Errorf("mustGetExecutable returned empty string")
	}
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		t.Errorf("Executable path %s does not exist", execPath)
	}
}

func Test_mustErr_NoError(t *testing.T) {
	logger := utils.NewLogger()
	mustErr(nil, "No error", logger)
}

func Test_mustErr_WithError(t *testing.T) {
	if os.Getenv("TEST_MUSTERR") == "1" {
		logger := utils.NewLogger()
		mustErr(os.ErrInvalid, "Test mustErr with error", logger)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=Test_mustErr_WithError")
	cmd.Env = append(os.Environ(), "TEST_MUSTERR=1")
	err := cmd.Run()
	if err == nil {
		t.Fatalf("Expected os.Exit but process did not exit")
	}
}

func Test_uninstall(t *testing.T) {
	tmpConfigDir := t.TempDir()
	fakeConfigDir := filepath.Join(tmpConfigDir, "wpprobe")
	if err := os.Mkdir(fakeConfigDir, 0755); err != nil {
		t.Fatalf("Failed to create fake config dir: %v", err)
	}

	tmpBinDir := t.TempDir()
	fakeBinary := filepath.Join(tmpBinDir, "wpprobe")
	if err := os.WriteFile(fakeBinary, []byte("dummy"), 0755); err != nil {
		t.Fatalf("Failed to create fake binary: %v", err)
	}

	origUserConfigFunc := getUserConfigDirFunc
	origExecutableFunc := getExecutableFunc
	getUserConfigDirFunc = func() (string, error) {
		return tmpConfigDir, nil
	}
	getExecutableFunc = func() (string, error) {
		return fakeBinary, nil
	}
	defer func() {
		getUserConfigDirFunc = origUserConfigFunc
		getExecutableFunc = origExecutableFunc
	}()

	uninstall()

	if _, err := os.Stat(fakeConfigDir); !os.IsNotExist(err) {
		t.Errorf("Fake config directory was not removed")
	}

	if _, err := os.Stat(fakeBinary); !os.IsNotExist(err) {
		t.Errorf("Fake binary was not removed")
	}
}
