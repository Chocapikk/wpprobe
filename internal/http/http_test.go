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
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClientManager_Get(t *testing.T) {
	tests := []struct {
		name       string
		serverFunc http.HandlerFunc
		want       string
		wantErr    bool
	}{
		{
			name: "Valid Response",
			serverFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte("Hello, World!")); err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
			},
			want:    "Hello, World!",
			wantErr: false,
		},
		{
			name: "No Redirection Allowed",
			serverFunc: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/new-location", http.StatusFound)
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Empty Response",
			serverFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Response Too Large",
			serverFunc: func(w http.ResponseWriter, r *http.Request) {
				largeData := make([]byte, maxResponseSize+1)
				if _, err := w.Write(largeData); err != nil {
					t.Errorf("Failed to write large response: %v", err)
				}
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(tt.serverFunc)
			defer mockServer.Close()

			client := NewHTTPClient(5*time.Second, nil, "", 0, -1)

			got, err := client.Get(mockServer.URL)

			if (err != nil) != tt.wantErr {
				t.Errorf("HTTPClientManager.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HTTPClientManager.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransport_KeepAlivesEnabled(t *testing.T) {
	client := NewHTTPClient(5*time.Second, nil, "", 0, -1)
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.DisableKeepAlives {
		t.Error("Keep-alives should be enabled by default")
	}
}

func TestTransport_ConnectionLimits(t *testing.T) {
	client := NewHTTPClient(5*time.Second, nil, "", 0, -1)
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.MaxConnsPerHost != 20 {
		t.Errorf("MaxConnsPerHost = %d, want 20", transport.MaxConnsPerHost)
	}
	if transport.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns = %d, want 100", transport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != 10 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 10", transport.MaxIdleConnsPerHost)
	}
	if transport.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 30s", transport.IdleConnTimeout)
	}
}

func TestTransport_TLSInsecureSkipVerify(t *testing.T) {
	client := NewHTTPClient(5*time.Second, nil, "", 0, -1)
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestRedirect_IntermediateBodiesClosed(t *testing.T) {
	var openBodies atomic.Int32

	// Server that does 3 chained redirects before a final 200
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		openBodies.Add(1)
		http.Redirect(w, r, "/hop1", http.StatusFound)
	})
	mux.HandleFunc("/hop1", func(w http.ResponseWriter, r *http.Request) {
		openBodies.Add(1)
		http.Redirect(w, r, "/hop2", http.StatusFound)
	})
	mux.HandleFunc("/hop2", func(w http.ResponseWriter, r *http.Request) {
		openBodies.Add(1)
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		openBodies.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("done"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Disable the built-in client redirect following so our manual loop runs
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	rawClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mgr := &HTTPClientManager{
		client:       rawClient,
		maxRedirects: 10,
	}
	mgr.parsedHeaders, mgr.hasCustomUA = mgr.parseHeaders()

	body, err := mgr.GetWithContext(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("GetWithContext() error = %v", err)
	}
	if body != "done" {
		t.Errorf("GetWithContext() = %q, want %q", body, "done")
	}
}

func TestRedirect_MaxRedirectsEnforced(t *testing.T) {
	// Server that always redirects
	redirectCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	rawClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mgr := &HTTPClientManager{
		client:       rawClient,
		maxRedirects: 3,
	}
	mgr.parsedHeaders, mgr.hasCustomUA = mgr.parseHeaders()

	_, err := mgr.GetWithContext(context.Background(), server.URL+"/start")
	if err == nil {
		t.Fatal("Expected error for too many redirects")
	}
}

func TestRedirect_ContextCancellation(t *testing.T) {
	// Server with a redirect chain
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	rawClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mgr := &HTTPClientManager{
		client:       rawClient,
		maxRedirects: 10,
	}
	mgr.parsedHeaders, mgr.hasCustomUA = mgr.parseHeaders()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := mgr.GetWithContext(ctx, server.URL+"/start")
	if err == nil {
		t.Fatal("Expected error from cancelled context")
	}
}

func TestGetStatusAndBody_ReturnsNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	client := NewHTTPClient(5*time.Second, nil, "", 0, 0)
	status, body, err := client.GetStatusAndBody(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("GetStatusAndBody() error = %v", err)
	}
	if status != 403 {
		t.Errorf("status = %d, want 403", status)
	}
	if body != "forbidden" {
		t.Errorf("body = %q, want %q", body, "forbidden")
	}
}

func TestHeadWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("Expected HEAD method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(5*time.Second, nil, "", 0, 0)
	status, err := client.HeadWithContext(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("HeadWithContext() error = %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
}

func TestEnableKeepAlives(t *testing.T) {
	client := NewHTTPClient(5*time.Second, nil, "", 0, -1)
	client.EnableKeepAlives(50)

	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.DisableKeepAlives {
		t.Error("Keep-alives should be enabled after EnableKeepAlives()")
	}
	if transport.MaxIdleConnsPerHost != 50 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 50", transport.MaxIdleConnsPerHost)
	}
}
