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
	"github.com/Chocapikk/wpprobe/internal/wordfence"
	"github.com/Chocapikk/wpprobe/internal/wpscan"
	"github.com/spf13/cobra"
)

var (
	updateWordfenceFunc = wordfence.UpdateWordfence
	updateWPScanFunc    = wpscan.UpdateWPScan
)

func runUpdateDb(cmd *cobra.Command, args []string) error {
	if err := updateWordfenceFunc(); err != nil {
		cmd.PrintErrf("Failed to update Wordfence database: %v\n", err)
		return err
	}

	if err := updateWPScanFunc(); err != nil {
		cmd.PrintErrf("Failed to update WPScan database: %v\n", err)
		return err
	}

	return nil
}

var updateDbCmd = &cobra.Command{
	Use:   "update-db",
	Short: "Update vulnerability databases",
	Long:  "Fetches the latest Wordfence and WPScan vulnerability databases and updates the local JSON files.",
	RunE:  runUpdateDb,
}
