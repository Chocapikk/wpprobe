// html_test.go
// Tests for HTML‐based plugin discovery functions.

package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	wphttp "github.com/Chocapikk/wpprobe/internal/http"
)

func sortedSlice(ss []string) []string {
	s := append([]string(nil), ss...)
	sort.Strings(s)
	return s
}

func TestExtractSlugsFromReader(t *testing.T) {
	tests := []struct {
		name       string
		html       string
		wantSlugs  []string
		wantThemes []string
	}{
		{
			name: "Single plugin in href",
			html: `<html><head>
				<link rel="stylesheet" href="https://example.com/wp-content/plugins/pluginA/style.css" />
			</head><body></body></html>`,
			wantSlugs: []string{"pluginA"},
		},
		{
			name: "Multiple plugins in href and src",
			html: `<html><body>
				<img src="/wp-content/plugins/pluginB/images/img.png" />
				<a href="http://foo/wp-content/plugins/pluginC/file.php"></a>
			</body></html>`,
			wantSlugs: []string{"pluginB", "pluginC"},
		},
		{
			name: "Duplicate slugs and nested paths",
			html: `<html><body>
				<script src="/wp-content/plugins/pluginA/js/app.js"></script>
				<link href="/wp-content/plugins/pluginA/css/app.css" rel="stylesheet">
				<img src="/some/other/path/pluginA/wp-content/plugins/pluginD/img.jpg">
			</body></html>`,
			wantSlugs: []string{"pluginA", "pluginD"},
		},
		{
			name:      "No plugin references",
			html:      `<html><body><p>No plugins here</p></body></html>`,
			wantSlugs: []string{},
		},
		{
			name: "Malformed attributes",
			html: `<html><body>
				<a href="wp-content/plugins//style.css"></a>
				<a href="/wp-content/plugins/"></a>
			</body></html>`,
			wantSlugs: []string{},
		},
		{
			name: "Theme in inline style block",
			html: `<html><head><style id="wp-webfonts-inline-css">
				@font-face{font-family:"DM Sans";src:url('/wp-content/themes/twentytwentythree/assets/fonts/dm-sans/DMSans-Regular.woff2') format('woff2');}
			</style></head><body></body></html>`,
			wantThemes: []string{"twentytwentythree"},
		},
		{
			name: "Theme in link attribute",
			html: `<html><head>
				<link rel="stylesheet" href="/wp-content/themes/flavor/style.css" />
			</head><body></body></html>`,
			wantThemes: []string{"flavor"},
		},
		{
			name: "Plugins and themes mixed in attributes and text",
			html: `<html><head>
				<link rel="stylesheet" href="/wp-content/plugins/jetpack/css/style.css" />
				<style>body{background:url('/wp-content/themes/flavor/img/bg.png')}</style>
			</head><body>
				<script src="/wp-content/plugins/woocommerce/js/app.js"></script>
			</body></html>`,
			wantSlugs:  []string{"jetpack", "woocommerce"},
			wantThemes: []string{"flavor"},
		},
		{
			name: "Plugin in inline script text",
			html: `<html><body>
				<script>var img = "/wp-content/plugins/hidden-plugin/img.png";</script>
			</body></html>`,
			wantSlugs: []string{"hidden-plugin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugins := make(map[string]struct{})
			themes := make(map[string]struct{})
			err := extractSlugsFromReader(strings.NewReader(tt.html), plugins, themes)
			if err != nil {
				t.Fatalf("extractSlugsFromReader returned error: %v", err)
			}

			var gotPlugins []string
			for slug := range plugins {
				gotPlugins = append(gotPlugins, slug)
			}
			gotPlugins = sortedSlice(gotPlugins)
			wantPlugins := sortedSlice(tt.wantSlugs)
			if !reflect.DeepEqual(gotPlugins, wantPlugins) {
				t.Errorf("plugins = %v, want %v", gotPlugins, wantPlugins)
			}

			var gotThemes []string
			for slug := range themes {
				gotThemes = append(gotThemes, slug)
			}
			gotThemes = sortedSlice(gotThemes)
			wantThemes := sortedSlice(tt.wantThemes)
			if !reflect.DeepEqual(gotThemes, wantThemes) {
				t.Errorf("themes = %v, want %v", gotThemes, wantThemes)
			}
		})
	}
}

func TestDiscoverPluginsFromHTML(t *testing.T) {
	const sampleHTML = `<!DOCTYPE html>
<html>
<head>
	<link rel="stylesheet" href="/wp-content/plugins/pluginX/css/style.css">
	<script src="http://host/wp-content/plugins/pluginY/js/app.js"></script>
</head>
<body>
	<img src="/wp-content/plugins/pluginZ/images/pic.png" alt="image">
	<a href="/some/other/path"></a>
</body>
</html>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleHTML))
	}))
	defer ts.Close()

	slugs, err := discoverPluginsFromHTML(context.TODO(), ts.URL, wphttp.Config{MaxRedirects: -1})
	if err != nil {
		t.Fatalf("discoverPluginsFromHTML returned error: %v", err)
	}

	got := sortedSlice(slugs)
	want := sortedSlice([]string{"pluginX", "pluginY", "pluginZ"})

	if !reflect.DeepEqual(got, want) {
		t.Errorf("discoverPluginsFromHTML = %v, want %v", got, want)
	}
}
