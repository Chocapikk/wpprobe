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

	"github.com/Chocapikk/wpprobe/internal/utils"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "wpprobe",
	Short:   "A fast WordPress plugin enumeration tool",
	Long:    `WPProbe is a high-speed WordPress plugin scanner that detects installed plugins and checks for known vulnerabilities using the Wordfence database.`,
	Version: utils.Version,
}

func Execute() {
	_, isLatest := utils.CheckLatestVersion(utils.Version)
	utils.DefaultLogger.PrintBanner(utils.Version, isLatest)

	if err := rootCmd.Execute(); err != nil {
		utils.DefaultLogger.Error(err.Error())
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(updateDbCmd)

	rootCmd.SetVersionTemplate("WPProbe version {{.utils.Version}}\n")

	rootCmd.SilenceErrors = true

	cobra.OnInitialize(func() {
		rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
			utils.DefaultLogger.Error(err.Error())
			return err
		})
		rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			if cmd.Parent() == nil {
				utils.DefaultLogger.Error("Unknown command: " + cmd.Name())
			}
			return nil
		}
	})
}
