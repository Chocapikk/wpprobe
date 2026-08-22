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
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/wordfence"
)

// Version lookups must share one client across the whole run. Building one per
// plugin gives each its own empty connection pool, so nothing is reused and
// every plugin pays a fresh handshake - which is what this used to do.
func TestCheckVulnerabilitiesReusesConnections(t *testing.T) {
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			if strings.HasSuffix(r.URL.Path, "readme.txt") {
				_, _ = w.Write([]byte("=== Plugin ===\nStable tag: 1.2.3\n"))
				return
			}
			w.WriteHeader(nethttp.StatusNotFound)
		}),
	)
	server.Config.ConnState = func(_ net.Conn, state nethttp.ConnState) {
		if state == nethttp.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	const pluginCount = 30
	plugins := make([]string, pluginCount)
	for index := range plugins {
		plugins[index] = "plugin-" + string(rune('a'+index%26))
	}

	versions, _ := CheckVulnerabilities(VulnerabilityCheckRequest{
		Target:  server.URL,
		Plugins: plugins,
		// One thread so the run cannot legitimately need a second connection.
		Opts:  ScanOptions{Threads: 1, File: "quiet"},
		Vulns: []wordfence.Vulnerability{},
		Ctx:   context.Background(),
	})

	if got := connections.Load(); got != 1 {
		t.Errorf("%d plugins opened %d connections, want 1: the client is not being shared", pluginCount, got)
	}
	if len(versions) == 0 {
		t.Fatal("no version was resolved, the lookups did not run at all")
	}
	for slug, version := range versions {
		if version != "1.2.3" {
			t.Errorf("version for %s = %q, want 1.2.3", slug, version)
			break
		}
	}
}
