package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newFakeWPServer(themes []string, plugins []string) *httptest.Server {
	mux := http.NewServeMux()

	body := "<html><head>"
	for _, t := range themes {
		body += fmt.Sprintf(`<link rel="stylesheet" href="/wp-content/themes/%s/style.css">`, t)
	}
	for _, p := range plugins {
		body += fmt.Sprintf(`<script src="/wp-content/plugins/%s/script.js"></script>`, p)
	}
	body += "</head><body></body></html>"

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-json" || r.URL.RawQuery == "rest_route=/" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"routes":{}}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, body)
	})

	mux.HandleFunc("/feed/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<html></html>")
	})
	mux.HandleFunc("/wp-content/uploads/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<html></html>")
	})
	mux.HandleFunc("/wp-content/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	return httptest.NewServer(mux)
}

func TestPerformHybridScan_PreservesThemesWhenNoPlugins(t *testing.T) {
	themeName := "theme-alpha"
	srv := newFakeWPServer([]string{themeName}, nil)
	defer srv.Close()

	ctx := ScanExecutionContext{
		Target: srv.URL,
		Opts: ScanOptions{
			Threads:  2,
			ScanMode: "hybrid",
			File:     "api",
		},
		Ctx: context.Background(),
	}

	result := performHybridScan(ctx)

	if len(result.Themes) == 0 {
		t.Fatal("expected at least one theme from hybrid scan, got none")
	}

	found := false
	for _, theme := range result.Themes {
		if theme == themeName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected theme %q in results, got: %v", themeName, result.Themes)
	}
}

func TestPerformHybridScan_PreservesThemesWithPlugins(t *testing.T) {
	themeName := "theme-beta"
	pluginName := "plugin-beta"
	srv := newFakeWPServer([]string{themeName}, []string{pluginName})
	defer srv.Close()

	ctx := ScanExecutionContext{
		Target: srv.URL,
		Opts: ScanOptions{
			Threads:  2,
			ScanMode: "hybrid",
			File:     "api",
		},
		Ctx: context.Background(),
	}

	result := performHybridScan(ctx)

	if len(result.Themes) == 0 {
		t.Fatal("expected at least one theme from hybrid scan when plugins exist, got none")
	}

	foundTheme := false
	for _, theme := range result.Themes {
		if theme == themeName {
			foundTheme = true
			break
		}
	}
	if !foundTheme {
		t.Errorf("expected theme %q in results, got: %v", themeName, result.Themes)
	}
}

func TestPerformStealthyScan_DiscoversThemes(t *testing.T) {
	srv := newFakeWPServer([]string{"theme-one", "theme-two"}, nil)
	defer srv.Close()

	ctx := ScanExecutionContext{
		Target: srv.URL,
		Opts: ScanOptions{
			Threads: 2,
			File:    "api",
		},
		Ctx: context.Background(),
	}

	result := performStealthyScan(ctx)

	if len(result.Themes) != 2 {
		t.Fatalf("expected 2 themes, got %d: %v", len(result.Themes), result.Themes)
	}
}
