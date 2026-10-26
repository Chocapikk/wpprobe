package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wphttp "github.com/Chocapikk/wpprobe/internal/http"
)

func TestStealthyScanDoesNotCalibratePluginFiles(t *testing.T) {
	var calibrationRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "no-existing-plugin-") {
			calibrationRequests.Add(1)
		}
		if r.URL.Path == "/wp-json" || r.URL.Query().Has("rest_route") {
			_, _ = w.Write([]byte(`{"routes":{}}`))
			return
		}
		_, _ = w.Write([]byte("<html><body>WordPress</body></html>"))
	}))
	defer server.Close()

	ScanSite(ScanSiteContext{
		Target: server.URL,
		Opts:   ScanOptions{ScanMode: "stealthy", Threads: 2, Context: context.Background()},
	})
	if got := calibrationRequests.Load(); got != 0 {
		t.Fatalf("stealthy scan made %d plugin calibration requests", got)
	}
}

func TestBruteforcePluginsStopsOnParentCancellation(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		BruteforcePlugins(BruteforceRequest{
			Target:  server.URL,
			Plugins: []string{"first-plugin", "second-plugin", "third-plugin"},
			Threads: 2,
			Context: ctx,
			HTTP:    wphttp.Config{},
			Calibrator: &Calibrator{
				available:    true,
				missStatuses: map[int]struct{}{404: {}},
			},
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("plugin probe did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bruteforce did not stop after parent cancellation")
	}
}
