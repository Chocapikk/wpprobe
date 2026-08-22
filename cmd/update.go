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
	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/version"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update WPProbe to the latest version",
	RunE: func(cmd *cobra.Command, args []string) error {
		build := version.Current()
		force, _ := cmd.Flags().GetBool("force")

		// Replacing a build from source with a release binary is a downgrade
		// whenever the checkout is ahead of the last tag, which it usually is.
		// It also silently discards local changes, so it needs to be asked for.
		if !build.Release && !force {
			logger.DefaultLogger.Warning(
				"This binary was built from source (" + build.Display + "), not installed from a release.",
			)
			logger.DefaultLogger.Info("Pull the repository and rebuild to update it.")
			logger.DefaultLogger.Info("To replace it with the latest release binary anyway: wpprobe update --force")
			return nil
		}

		if err := version.AutoUpdate(build.Comparable); err != nil {
			logger.DefaultLogger.Error("Update failed: " + err.Error())
			return err
		}
		logger.DefaultLogger.Success("Update completed successfully!")
		return nil
	},
}

func init() {
	updateCmd.Flags().Bool("force", false, "Replace a build from source with the latest release binary")
}
