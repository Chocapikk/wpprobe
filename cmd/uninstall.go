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
	"path/filepath"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/spf13/cobra"
)

var getUserConfigDirFunc = os.UserConfigDir
var getExecutableFunc = os.Executable

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstalls WPProbe and removes all related files and the binary",
	Run: func(cmd *cobra.Command, args []string) {
		uninstall()
	},
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}

func uninstall() {
	logger := utils.NewLogger()

	configDir := mustGetUserConfigDir(logger)
	removeDir(filepath.Join(configDir, "wpprobe"), "WPProbe configuration", logger)

	execPath := mustGetExecutable(logger)
	removeFile(execPath, "WPProbe binary", logger)

	logger.Success("WPProbe has been fully uninstalled.")
}

func removeDir(path, description string, logger *utils.Logger) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Warning(description + " not found. Nothing to remove.")
		return
	}
	mustErr(os.RemoveAll(path), "Failed to remove "+description, logger)
}

func removeFile(path, description string, logger *utils.Logger) {
	mustErr(os.Remove(path), "Failed to remove "+description, logger)
}

func mustGetUserConfigDir(logger *utils.Logger) string {
	dir, err := getUserConfigDirFunc()
	if err != nil {
		logger.Error("Failed to get user config directory: " + err.Error())
		os.Exit(1)
	}
	return dir
}

func mustGetExecutable(logger *utils.Logger) string {
	execPath, err := getExecutableFunc()
	if err != nil {
		logger.Error("Failed to get executable path: " + err.Error())
		os.Exit(1)
	}
	return execPath
}

func mustErr(err error, msg string, logger *utils.Logger) {
	if err != nil {
		logger.Error(msg + ": " + err.Error())
		os.Exit(1)
	}
}
