package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func TestPerformHybridScan_RejectsRouteOnlyPlugin(t *testing.T) {
	var routeOnlyProbes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/wp-content/plugins/op-kassa-for-woocommerce/") {
			routeOnlyProbes.Add(1)
		}
		switch {
		case r.URL.Path == "/":
			_, _ = fmt.Fprint(w, `<script src="/wp-content/plugins/woocommerce/assets/app.js"></script>`)
		case r.URL.Path == "/wp-json" || r.URL.Query().Has("rest_route"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"routes":{"/wc/v3":{}}}`)
		case r.URL.Path == "/wp-content/plugins/woocommerce/woocommerce.php":
			_, _ = fmt.Fprint(w, "")
		case r.URL.Path == "/wp-content/plugins/woocommerce/readme.txt":
			_, _ = fmt.Fprint(w, "Stable tag: 11.2.1")
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "plugins.txt")
	if err := os.WriteFile(list, []byte("woocommerce\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := ScanExecutionContext{
		Target: srv.URL,
		Opts: ScanOptions{
			Threads:    4,
			ScanMode:   "hybrid",
			PluginList: list,
			File:       "api",
		},
		Ctx: context.Background(),
	}

	result := performHybridScan(ctx)
	if len(result.Plugins) != 1 || result.Plugins[0] != "woocommerce" {
		t.Fatalf("hybrid plugins = %v, want only woocommerce", result.Plugins)
	}
	if _, exists := result.PluginResult.Plugins["op-kassa-for-woocommerce"]; exists {
		t.Fatal("route-only candidate survived direct verification")
	}
	if routeOnlyProbes.Load() == 0 {
		t.Fatal("route-only candidate was skipped instead of verified")
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
