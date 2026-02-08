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
}

// NewClient creates an HTTPClientManager from this config.
// If ExternalClient is set, it wraps that client. Otherwise creates a new one.
func (c Config) NewClient(timeout time.Duration) *HTTPClientManager {
	if c.ExternalClient != nil {
		return NewHTTPClientFromExternal(c.ExternalClient, c.Headers, c.RateLimit)
	}
	return NewHTTPClient(timeout, c.Headers, c.Proxy, c.RateLimit, c.MaxRedirects)
}
