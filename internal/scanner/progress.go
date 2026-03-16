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

// Progress defines the interface for progress reporting.
// The real implementation lives in internal/progress and is only
// imported by CLI code, keeping TUI dependencies out of the library path.
type Progress interface {
	Increment()
	Finish()
	SetTotal(int)
	SetMessage(string)
	RenderBlank()
	ClearLine()
	Bprintln(a ...interface{}) (int, error)
}

func isFileScan(opts ScanOptions) bool {
	return opts.File != ""
}

func clearProgressLine(p Progress, isFileScan bool) {
	if p != nil && !isFileScan {
		p.ClearLine()
	}
}

func setProgressMessage(p Progress, isFileScan bool, message string) {
	if p != nil && !isFileScan {
		p.SetMessage(message)
	}
}

func finishProgressIfNeeded(p Progress) {
	if p != nil {
		p.Finish()
	}
}

func setupBruteforceProgress(opts ScanOptions, parentProgress Progress, pluginCount int) Progress {
	if parentProgress == nil {
		if opts.NewProgress != nil {
			return opts.NewProgress(pluginCount, "Bruteforcing plugins...")
		}
		return nil
	}

	if opts.File == "" {
		parentProgress.SetTotal(pluginCount)
		parentProgress.SetMessage("Bruteforcing plugins...")
	}
	return parentProgress
}

func finishBruteforceProgress(p Progress, opts ScanOptions) {
	if p != nil && opts.File == "" {
		p.Finish()
	}
}
