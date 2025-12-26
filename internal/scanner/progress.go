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

package scanner

import (
	"github.com/Chocapikk/wpprobe/internal/progress"
)

func isFileScan(opts ScanOptions) bool {
	return opts.File != ""
}

func clearProgressLine(progress *progress.ProgressManager, isFileScan bool) {
	if progress != nil && !isFileScan {
		progress.ClearLine()
	}
}

func setProgressMessage(progress *progress.ProgressManager, isFileScan bool, message string) {
	if progress != nil && !isFileScan {
		progress.SetMessage(message)
	}
}

func finishProgressIfNeeded(progress *progress.ProgressManager) {
	if progress != nil {
		progress.Finish()
	}
}

func setupBruteforceProgress(ctx BruteforceProgressContext) *progress.ProgressManager {
	if ctx.ParentProgress == nil {
		return progress.NewProgressBar(ctx.PluginCount, "🔎 Bruteforcing plugins...")
	}

	if ctx.Opts.File == "" {
		ctx.ParentProgress.SetTotal(ctx.PluginCount)
		ctx.ParentProgress.SetMessage("🔎 Bruteforcing plugins...")
	}
	return ctx.ParentProgress
}

func finishBruteforceProgress(progress *progress.ProgressManager, opts ScanOptions) {
	if progress != nil && opts.File == "" {
		progress.Finish()
	}
}

