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
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	mu          sync.Mutex
	tokens      int
	maxTokens   int
	refillRate  time.Duration
	lastRefill  time.Time
}

// NewRateLimiter creates a new rate limiter with the specified requests per second.
// If rps is 0 or negative, returns nil (no rate limiting).
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return nil
	}

	refillInterval := time.Second / time.Duration(rps)
	if refillInterval < time.Millisecond {
		refillInterval = time.Millisecond
	}

	return &RateLimiter{
		tokens:     rps,
		maxTokens:  rps,
		refillRate: refillInterval,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available.
// If the rate limiter is nil (disabled), returns immediately.
func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	if elapsed > 0 {
		tokensToAdd := int(elapsed / rl.refillRate)
		if tokensToAdd > 0 {
			rl.tokens = min(rl.tokens+tokensToAdd, rl.maxTokens)
			rl.lastRefill = now
		}
	}

	if rl.tokens > 0 {
		rl.tokens--
		return
	}

	waitTime := rl.refillRate - elapsed
	if waitTime > 0 {
		rl.mu.Unlock()
		time.Sleep(waitTime)
		rl.mu.Lock()
		rl.tokens = rl.maxTokens - 1
		rl.lastRefill = time.Now()
	} else {
		rl.tokens = 0
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

