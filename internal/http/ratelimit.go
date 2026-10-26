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
	"context"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter.
type RateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
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
		tokens:     float64(rps),
		maxTokens:  rps,
		refillRate: refillInterval,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available.
// If the rate limiter is nil (disabled), returns immediately.
func (rl *RateLimiter) Wait() {
	_ = rl.WaitContext(context.Background())
}

// WaitContext waits for a token, or returns when ctx is cancelled.
func (rl *RateLimiter) WaitContext(ctx context.Context) error {
	if rl == nil {
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rl.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(rl.lastRefill)
		if elapsed > 0 {
			rl.tokens += float64(elapsed) / float64(rl.refillRate)
			if rl.tokens > float64(rl.maxTokens) {
				rl.tokens = float64(rl.maxTokens)
			}
			rl.lastRefill = now
		}
		if rl.tokens >= 1 {
			rl.tokens--
			rl.mu.Unlock()
			return nil
		}
		waitTime := time.Duration((1 - rl.tokens) * float64(rl.refillRate))
		rl.mu.Unlock()
		timer := time.NewTimer(waitTime)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}
