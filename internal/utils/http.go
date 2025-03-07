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
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/corpix/uarand"
)

const maxResponseSizeMB = 50

var maxResponseSize = maxResponseSizeMB * 1024 * 1024

const maxRedirects = 10

type HTTPClientManager struct {
	client    *http.Client
	userAgent string
}

func NewHTTPClient(timeout time.Duration) *HTTPClientManager {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
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
		client:    client,
		userAgent: uarand.GetRandom(),
	}
}

func (h *HTTPClientManager) Get(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", errors.New("failed to create request: " + err.Error())
	}

	req.Header.Set("User-Agent", h.userAgent)

	resp, err := h.client.Do(req)
	if err != nil {
		return "", errors.New("request failed: " + err.Error())
	}
	defer resp.Body.Close()

	redirects := 0
	for resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if redirects >= maxRedirects {
			return "", errors.New("stopped after max redirects")
		}
		location, err := resp.Location()
		if err != nil {
			return "", errors.New("failed to get redirect location")
		}
		resp, err = h.client.Get(location.String())
		if err != nil {
			return "", errors.New("redirect request failed: " + err.Error())
		}
		redirects++
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("non-success status code: " + resp.Status)
	}

	limited := io.LimitReader(resp.Body, int64(maxResponseSize))
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", errors.New("failed to read response body: " + err.Error())
	}

	if len(data) == 0 {
		return "", errors.New("empty response")
	}

	if len(data) >= maxResponseSize {
		return "", errors.New("response too large")
	}

	return string(data), nil
}
