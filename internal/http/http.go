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

const maxResponseSizeMB = 50

var maxResponseSize = maxResponseSizeMB * 1024 * 1024

const maxRedirects = 10

type HTTPClientManager struct {
	client     *http.Client
	userAgent  string
	headers    []string
	rateLimiter *RateLimiter
}

func NewHTTPClient(timeout time.Duration, headers []string, proxyURL string, rps int) *HTTPClientManager {
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("stopped after max redirects")
			}
			return nil
		},
	}

	return &HTTPClientManager{
		client:      client,
		userAgent:   uarand.GetRandom(),
		headers:     headers,
		rateLimiter: NewRateLimiter(rps),
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

func (h *HTTPClientManager) Get(url string) (string, error) {
	if h.rateLimiter != nil {
		h.rateLimiter.Wait()
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	parsedHeaders, hasUA := h.parseHeaders()

	if hasUA {
		req.Header.Set("User-Agent", parsedHeaders["User-Agent"])
	} else {
		req.Header.Set("User-Agent", h.userAgent)
	}

	for key, value := range parsedHeaders {
		if !strings.EqualFold(key, "User-Agent") {
			req.Header.Add(key, value)
		}
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirects := 0
	for resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if redirects >= maxRedirects {
			return "", errors.New("stopped after max redirects")
		}
		location, err := resp.Location()
		if err != nil {
			return "", fmt.Errorf("failed to get redirect location: %w", err)
		}
		resp, err = h.client.Get(location.String())
		if err != nil {
			return "", fmt.Errorf("redirect request failed: %w", err)
		}
		redirects++
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
