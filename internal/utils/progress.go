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
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/k0kubun/go-ansi"
	"github.com/schollz/progressbar/v3"
)

type ProgressManager struct {
	bar *progressbar.ProgressBar
	mu  sync.Mutex
}

func NewProgressBar(total int, description string) *ProgressManager {
	bar := progressbar.NewOptions(total,
		progressbar.OptionSetWriter(ansi.NewAnsiStderr()),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowIts(),
		progressbar.OptionSetDescription("[cyan]"+description),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "▓",
			SaucerHead:    "▒",
			SaucerPadding: "░",
			BarStart:      "⏳ ",
			BarEnd:        " ⏳",
		}),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(100*time.Millisecond),
	)

	pm := &ProgressManager{bar: bar}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		pm.Finish()
		os.Exit(1)
	}()

	return pm
}

func (p *ProgressManager) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.bar.Add(1)
}

func (p *ProgressManager) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.bar.Finish()
}

func (p *ProgressManager) RenderBlank() {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.bar.RenderBlank()
}

func (p *ProgressManager) ClearLine() {
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Fprint(os.Stdout, "\r\033[K")
	time.Sleep(10 * time.Millisecond)
	os.Stdout.Sync()
}

func (p *ProgressManager) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(data)
	_ = p.bar.Add(n)
	return n, nil
}

func (p *ProgressManager) Bprintln(a ...interface{}) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return progressbar.Bprintln(p.bar, a...)
}

func (p *ProgressManager) Bprintf(format string, a ...interface{}) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return progressbar.Bprintf(p.bar, format, a...)
}

func (p *ProgressManager) SetTotal(total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bar.ChangeMax(total)
}

func (p *ProgressManager) SetMessage(description string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bar.Describe("[cyan]" + description)
}
