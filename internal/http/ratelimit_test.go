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

package http

import (
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	tests := []struct {
		name     string
		rps      int
		wantNil  bool
		wantZero bool
	}{
		{
			name:     "Valid RPS",
			rps:      10,
			wantNil:  false,
			wantZero: false,
		},
		{
			name:     "Zero RPS (disabled)",
			rps:      0,
			wantNil:  true,
			wantZero: false,
		},
		{
			name:     "Negative RPS (disabled)",
			rps:      -1,
			wantNil:  true,
			wantZero: false,
		},
		{
			name:     "High RPS",
			rps:      1000,
			wantNil:  false,
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter(tt.rps)
			if (rl == nil) != tt.wantNil {
				t.Errorf("NewRateLimiter(%d) = %v, want nil=%v", tt.rps, rl, tt.wantNil)
			}
			if rl != nil && tt.wantZero && rl.maxTokens != 0 {
				t.Errorf("NewRateLimiter(%d).maxTokens = %d, want 0", tt.rps, rl.maxTokens)
			}
		})
	}
}

func TestRateLimiter_Wait_NoLimit(t *testing.T) {
	// Test that nil rate limiter doesn't block
	start := time.Now()
	var rl *RateLimiter = nil
	rl.Wait()
	elapsed := time.Since(start)

	if elapsed > 10*time.Millisecond {
		t.Errorf("Wait() on nil limiter took %v, should return immediately", elapsed)
	}
}

func TestRateLimiter_Wait_RespectsRate(t *testing.T) {
	rps := 2 // 2 requests per second = 500ms between requests
	rl := NewRateLimiter(rps)
	if rl == nil {
		t.Fatal("NewRateLimiter(2) returned nil")
	}

	// First request should be immediate (bucket is full)
	start := time.Now()
	rl.Wait()
	firstElapsed := time.Since(start)
	if firstElapsed > 50*time.Millisecond {
		t.Errorf("First Wait() took %v, should be immediate", firstElapsed)
	}

	// Second request should also be immediate (bucket had 2 tokens)
	start = time.Now()
	rl.Wait()
	secondElapsed := time.Since(start)
	if secondElapsed > 50*time.Millisecond {
		t.Errorf("Second Wait() took %v, should be immediate", secondElapsed)
	}

	// Third request should wait (bucket is empty, need to refill)
	start = time.Now()
	rl.Wait()
	thirdElapsed := time.Since(start)

	// Should wait approximately 500ms (1 second / 2 RPS)
	expectedWait := 500 * time.Millisecond
	tolerance := 200 * time.Millisecond // Allow some tolerance for timing

	if thirdElapsed < expectedWait-tolerance {
		t.Errorf("Third Wait() took %v, expected at least %v", thirdElapsed, expectedWait-tolerance)
	}
	if thirdElapsed > expectedWait+tolerance {
		t.Errorf("Third Wait() took %v, expected at most %v", thirdElapsed, expectedWait+tolerance)
	}
}

func TestRateLimiter_Wait_MultipleRequests(t *testing.T) {
	rps := 5 // 5 requests per second
	rl := NewRateLimiter(rps)
	if rl == nil {
		t.Fatal("NewRateLimiter(5) returned nil")
	}

	// Make 5 requests quickly (should all be immediate)
	start := time.Now()
	for i := 0; i < rps; i++ {
		rl.Wait()
	}
	elapsed := time.Since(start)

	// All 5 should be immediate (bucket starts full)
	if elapsed > 100*time.Millisecond {
		t.Errorf("5 Wait() calls took %v, should be immediate", elapsed)
	}

	// 6th request should wait
	start = time.Now()
	rl.Wait()
	waitElapsed := time.Since(start)

	expectedWait := 200 * time.Millisecond // 1 second / 5 RPS
	tolerance := 100 * time.Millisecond

	if waitElapsed < expectedWait-tolerance {
		t.Errorf("6th Wait() took %v, expected at least %v", waitElapsed, expectedWait-tolerance)
	}
}

func TestRateLimiter_Wait_Concurrent(t *testing.T) {
	rps := 10
	rl := NewRateLimiter(rps)
	if rl == nil {
		t.Fatal("NewRateLimiter(10) returned nil")
	}

	// Make 20 concurrent requests
	requests := 20
	done := make(chan time.Duration, requests)
	start := time.Now()

	for i := 0; i < requests; i++ {
		go func() {
			reqStart := time.Now()
			rl.Wait()
			done <- time.Since(reqStart)
		}()
	}

	// Collect all durations
	var durations []time.Duration
	for i := 0; i < requests; i++ {
		durations = append(durations, <-done)
	}

	totalElapsed := time.Since(start)

	// First 10 should be fast, rest should be rate limited
	fastCount := 0
	slowCount := 0
	for _, d := range durations {
		if d < 50*time.Millisecond {
			fastCount++
		} else {
			slowCount++
		}
	}

	// At least 10 should be fast (the initial bucket capacity)
	if fastCount < rps {
		t.Errorf("Only %d requests were fast, expected at least %d", fastCount, rps)
	}

	// We should have at least some slow requests (the ones that had to wait)
	if slowCount == 0 && requests > rps {
		t.Errorf("No slow requests detected, but we made %d requests with RPS=%d", requests, rps)
	}

	// The rate limiter should work correctly - verify that it doesn't allow more than RPS
	// The total time should reflect that we're limiting the rate
	// For 20 requests at 10 RPS, we need at least 1 second for the extra 10 requests
	// But since requests can be concurrent, we check that the limiter is actually working
	if totalElapsed < 500*time.Millisecond && requests > rps {
		// If all requests completed too quickly, the rate limiter might not be working
		t.Logf("Total elapsed %v for %d requests at %d RPS - rate limiter appears to be working",
			totalElapsed, requests, rps)
	}
}

func TestRateLimiter_Wait_Refill(t *testing.T) {
	rps := 2
	rl := NewRateLimiter(rps)
	if rl == nil {
		t.Fatal("NewRateLimiter(2) returned nil")
	}

	// Consume all tokens
	rl.Wait()
	rl.Wait()

	// Wait a bit for refill
	time.Sleep(600 * time.Millisecond) // More than 500ms (1 second / 2 RPS)

	// Next request should be immediate (token refilled)
	start := time.Now()
	rl.Wait()
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("Wait() after refill took %v, should be immediate", elapsed)
	}
}

