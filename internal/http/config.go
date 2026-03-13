package http

import (
	stdhttp "net/http"
	"time"
)

// Config contains HTTP-related configuration for making requests.
type Config struct {
	Headers        []string
	Proxy          string
	RateLimit      int              // Requests per second (0 = unlimited)
	MaxRedirects   int              // Maximum redirects to follow (0 = disable, -1 = default: 10)
	ExternalClient *stdhttp.Client  // External HTTP client (optional, for connection pooling)
	SharedLimiter  *RateLimiter     // Shared rate limiter across all clients (set once, reused)
}

// NewClient creates an HTTPClientManager from this config.
// If SharedLimiter is set, all clients share that limiter.
// Otherwise a new per-client limiter is created from RateLimit.
func (c Config) NewClient(timeout time.Duration) *HTTPClientManager {
	limiter := c.SharedLimiter
	if limiter == nil && c.RateLimit > 0 {
		limiter = NewRateLimiter(c.RateLimit)
	}
	if c.ExternalClient != nil {
		return newHTTPClientFromExternalWithLimiter(c.ExternalClient, c.Headers, limiter)
	}
	return newHTTPClientWithLimiter(timeout, c.Headers, c.Proxy, limiter, c.MaxRedirects)
}
