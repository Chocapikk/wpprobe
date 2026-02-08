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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/corpix/uarand"
)

var maxResponseSize = 1024 * 1024 // 1MB

const defaultMaxRedirects = 10

type HTTPClientManager struct {
	client        *http.Client
	userAgent     string
	headers       []string
	parsedHeaders map[string]string
	hasCustomUA   bool
	rateLimiter   *RateLimiter
	maxRedirects  int
}

func NewHTTPClient(timeout time.Duration, headers []string, proxyURL string, rps int, maxRedirects int) *HTTPClientManager {
	if maxRedirects < 0 {
		maxRedirects = defaultMaxRedirects
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}

	// Configure proxy if provided
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			logger.DefaultLogger.Warning(fmt.Sprintf("Invalid proxy URL %q: %v, ignoring proxy", proxyURL, err))
		} else {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	if maxRedirects == 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("stopped after max redirects")
			}
			return nil
		}
	}

	mgr := &HTTPClientManager{
		client:       client,
		userAgent:    uarand.GetRandom(),
		headers:      headers,
		rateLimiter:  NewRateLimiter(rps),
		maxRedirects: maxRedirects,
	}
	mgr.parsedHeaders, mgr.hasCustomUA = mgr.parseHeaders()
	return mgr
}

// NewHTTPClientFromExternal wraps an external http.Client (e.g., from a connection pool).
// This allows reusing an existing client instead of creating a new one.
// The external client is used as-is; headers and rate limiting are still applied.
func NewHTTPClientFromExternal(externalClient *http.Client, headers []string, rps int) *HTTPClientManager {
	mgr := &HTTPClientManager{
		client:       externalClient,
		userAgent:    "",
		headers:      headers,
		rateLimiter:  NewRateLimiter(rps),
		maxRedirects: 0,
	}
	mgr.parsedHeaders, mgr.hasCustomUA = mgr.parseHeaders()
	return mgr
}

// EnableKeepAlives enables HTTP connection reuse. Use this when making
// many requests to the same host (e.g. bruteforce scanning).
func (h *HTTPClientManager) EnableKeepAlives(maxConnsPerHost int) {
	if t, ok := h.client.Transport.(*http.Transport); ok {
		t.DisableKeepAlives = false
		t.MaxIdleConnsPerHost = maxConnsPerHost
		t.IdleConnTimeout = 30 * time.Second
	}
}

func (h *HTTPClientManager) parseHeaders() (map[string]string, bool) {
	headers := make(map[string]string)
	hasUA := false

	for _, hdr := range h.headers {
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if strings.EqualFold(key, "User-Agent") {
			hasUA = true
		}
		headers[key] = value
	}

	return headers, hasUA
}

func (h *HTTPClientManager) waitForRate(ctx context.Context) error {
	if h.rateLimiter == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		h.rateLimiter.Wait()
		return nil
	}
}

func (h *HTTPClientManager) applyHeaders(req *http.Request) {
	if h.hasCustomUA {
		req.Header.Set("User-Agent", h.parsedHeaders["User-Agent"])
	} else if h.userAgent != "" {
		req.Header.Set("User-Agent", h.userAgent)
	}
	for key, value := range h.parsedHeaders {
		if !strings.EqualFold(key, "User-Agent") {
			req.Header.Add(key, value)
		}
	}
}

func (h *HTTPClientManager) newRequest(ctx context.Context, method, url string) (*http.Request, error) {
	if err := h.waitForRate(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	h.applyHeaders(req)
	return req, nil
}

func (h *HTTPClientManager) doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	resp, err := h.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return resp, nil
}

// HeadWithContext sends a HEAD request and returns the HTTP status code.
// No body is read. Useful for fast existence checks (e.g. 403 vs 404).
func (h *HTTPClientManager) HeadWithContext(ctx context.Context, url string) (int, error) {
	req, err := h.newRequest(ctx, "HEAD", url)
	if err != nil {
		return 0, err
	}
	resp, err := h.doRequest(ctx, req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func (h *HTTPClientManager) Get(url string) (string, error) {
	return h.GetWithContext(context.Background(), url)
}

func (h *HTTPClientManager) GetWithContext(ctx context.Context, url string) (string, error) {
	req, err := h.newRequest(ctx, "GET", url)
	if err != nil {
		return "", err
	}
	resp, err := h.doRequest(ctx, req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if h.maxRedirects == 0 {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return "", errors.New("redirects disabled")
		}
	} else {
		redirects := 0
		for resp.StatusCode >= 300 && resp.StatusCode < 400 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			default:
			}
			if redirects >= h.maxRedirects {
				return "", errors.New("stopped after max redirects")
			}
		location, err := resp.Location()
		if err != nil {
			return "", fmt.Errorf("failed to get redirect location: %w", err)
		}
		redirectReq, err := http.NewRequestWithContext(ctx, "GET", location.String(), nil)
		if err != nil {
			return "", fmt.Errorf("failed to create redirect request: %w", err)
		}
			resp, err = h.client.Do(redirectReq)
			if err != nil {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				return "", fmt.Errorf("redirect request failed: %w", err)
			}
			redirects++
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("non-success status code: %s", resp.Status)
	}

	limited := io.LimitReader(resp.Body, int64(maxResponseSize))
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if len(data) == 0 {
		return "", errors.New("empty response")
	}

	if len(data) >= maxResponseSize {
		return "", errors.New("response too large")
	}

	return string(data), nil
}

func NormalizeURL(url string) string {
	url = strings.TrimSuffix(url, "/")
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	return url
}

func SplitLines(data []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
