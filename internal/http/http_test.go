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
	"net/http"
	"net/http/httptest"
	"reflect"
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
