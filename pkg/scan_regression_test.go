package wpprobe_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	wpprobe "github.com/Chocapikk/wpprobe/pkg"
)

func TestScanReturnsCancellation(t *testing.T) {
	s, err := wpprobe.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := s.Scan(wpprobe.Config{Target: "http://127.0.0.1:1", Context: ctx})
	if !errors.Is(err, context.Canceled) || result != nil {
		t.Fatalf("Scan() = (%v, %v), want (nil, context.Canceled)", result, err)
	}
}

func TestScanReturnsCancellationDuringDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		_, _ = fmt.Fprint(w, "<html></html>")
	}))
	defer server.Close()
	defer cancel()

	s, err := wpprobe.New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(wpprobe.Config{Target: server.URL, Context: ctx})
	if !errors.Is(err, context.Canceled) || result != nil {
		t.Fatalf("Scan() = (%v, %v), want (nil, context.Canceled)", result, err)
	}
}

func TestScanPreservesRouteConfidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-json" || r.URL.Query().Has("rest_route") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"routes":{"/wc/v3":{},"/wp/v2/affiliate_link":{}}}`)
			return
		}
		_, _ = fmt.Fprint(w, "<html></html>")
	}))
	defer server.Close()

	s, err := wpprobe.New()
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(wpprobe.Config{Target: server.URL, NoCheckVersion: true})
	if err != nil {
		t.Fatal(err)
	}
	foundConfidence := false
	foundAmbiguity := false
	for _, plugin := range result.Plugins {
		if plugin.Name == "op-kassa-for-woocommerce" {
			if plugin.Confidence != 33.33 {
				t.Fatalf("confidence = %.2f, want 33.33", plugin.Confidence)
			}
			foundConfidence = true
		}
		if plugin.Name == "affiliate-advantage" {
			if !plugin.Ambiguous {
				t.Fatal("ambiguous REST signature was reported as unambiguous")
			}
			foundAmbiguity = true
		}
	}
	if !foundConfidence || !foundAmbiguity {
		t.Fatalf("missing REST candidates (confidence=%v, ambiguous=%v)", foundConfidence, foundAmbiguity)
	}
}

func TestScanHonorsZeroRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/home", http.StatusFound)
		case "/home":
			_, _ = fmt.Fprint(w, `<script src="/wp-content/plugins/redirected-plugin/app.js"></script>`)
		case "/wp-json":
			_, _ = fmt.Fprint(w, `{"routes":{}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	s, err := wpprobe.New()
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := s.Scan(wpprobe.Config{Target: server.URL, MaxRedirects: 0, NoCheckVersion: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked.Plugins) != 0 {
		t.Fatalf("zero redirects found plugins: %+v", blocked.Plugins)
	}
	followed, err := s.Scan(wpprobe.Config{Target: server.URL, MaxRedirects: -1, NoCheckVersion: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(followed.Plugins) != 1 || followed.Plugins[0].Name != "redirected-plugin" {
		t.Fatalf("default redirects found plugins: %+v", followed.Plugins)
	}
}
