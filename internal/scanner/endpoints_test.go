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

package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	wphttp "github.com/Chocapikk/wpprobe/internal/http"
)

func TestFetchEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		mockServer func(w http.ResponseWriter, r *http.Request)
		headers    []string
		want       []string
	}{
		{
			name: "Valid response with routes and header present",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Test") != "value" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				response := map[string]interface{}{
					"routes": map[string]interface{}{
						"/wp/v2/posts":      nil,
						"/wp/v2/comments":   nil,
						"/wp/v2/categories": nil,
					},
				}
				_ = json.NewEncoder(w).Encode(response)
			},
			headers: []string{"X-Test: value"},
			want:    []string{"/wp/v2/posts", "/wp/v2/comments", "/wp/v2/categories"},
		},
		{
			name: "Valid response with routes but header missing",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Test") == "" {
					response := map[string]interface{}{
						"routes": map[string]interface{}{
							"/wp/v2/posts": nil,
						},
					}
					_ = json.NewEncoder(w).Encode(response)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
			},
			headers: nil,
			want:    []string{"/wp/v2/posts"},
		},
		{
			name: "Response without routes",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": "No routes here",
				})
			},
			headers: nil,
			want:    []string{},
		},
		{
			name: "Invalid JSON response",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("{invalid-json"))
			},
			headers: nil,
			want:    []string{},
		},
		{
			name: "HTTP error response",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			headers: nil,
			want:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.mockServer))
			defer server.Close()

			got := FetchEndpoints(context.TODO(), server.URL, wphttp.Config{Headers: tt.headers, MaxRedirects: -1})

			sort.Strings(got)
			sort.Strings(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FetchEndpoints() = %v, want %v", got, tt.want)
			}
		})
	}
}
