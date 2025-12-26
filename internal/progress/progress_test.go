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

package progress

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestNewProgressBar(t *testing.T) {
	pm := NewProgressBar(10, "Testing Progress Bar")
	if pm == nil || pm.bar == nil {
		t.Errorf("NewProgressBar() failed to create progress bar")
	}
}

func TestProgressManager_Increment(t *testing.T) {
	pm := NewProgressBar(5, "Increment Test")
	for i := 0; i < 5; i++ {
		pm.Increment()
	}
	if pm.bar.State().CurrentPercent != 1.0 {
		t.Errorf("Progress bar did not reach 100%%, got %v", pm.bar.State().CurrentPercent*100)
	}
	pm.Finish()
}

func TestProgressManager_Finish(t *testing.T) {
	pm := NewProgressBar(3, "Finish Test")
	pm.Increment()
	pm.Finish()

	if !pm.bar.IsFinished() {
		t.Errorf("Progress bar did not finish as expected")
	}
}

func TestProgressManager_RenderBlank(t *testing.T) {
	pm := NewProgressBar(3, "Render Blank Test")
	pm.RenderBlank()
}

func TestProgressManager_Write(t *testing.T) {
	pm := NewProgressBar(5, "Write Test")
	data := []byte("12345")
	n, err := pm.Write(data)
	if err != nil {
		t.Errorf("ProgressManager.Write() error = %v", err)
	}
	if n != len(data) {
		t.Errorf("ProgressManager.Write() wrote %d bytes, want %d", n, len(data))
	}
}

func TestProgressManager_Bprintln(t *testing.T) {
	pm := NewProgressBar(3, "Bprintln Test")
	n, err := pm.Bprintln("This is a test line")
	if err != nil {
		t.Errorf("ProgressManager.Bprintln() error = %v", err)
	}
	if n == 0 {
		t.Errorf("ProgressManager.Bprintln() wrote 0 bytes")
	}
}

func TestProgressManager_Bprintf(t *testing.T) {
	pm := NewProgressBar(3, "Bprintf Test")
	n, err := pm.Bprintf("Test %d %s", 123, "format")
	if err != nil {
		t.Errorf("ProgressManager.Bprintf() error = %v", err)
	}
	if n == 0 {
		t.Errorf("ProgressManager.Bprintf() wrote 0 bytes")
	}
}

func TestProgressManager_SignalHandling(t *testing.T) {
	pm := NewProgressBar(5, "Signal Handling Test")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		time.Sleep(500 * time.Millisecond)
		signalChan <- os.Interrupt
	}()

	select {
	case <-signalChan:
		pm.Finish()
	case <-time.After(1 * time.Second):
		t.Errorf("Signal handling did not complete in time")
	}
}

func TestProgressManager_ThreadSafety(t *testing.T) {
	pm := NewProgressBar(100, "Thread Safety Test")
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				pm.Increment()
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if pm.bar.State().CurrentPercent != 1.0 {
		t.Errorf(
			"Progress bar did not reach 100%% in concurrent usage, got %v",
			pm.bar.State().CurrentPercent*100,
		)
	}

	pm.Finish()
}
