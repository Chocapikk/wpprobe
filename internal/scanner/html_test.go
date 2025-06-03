// html_test.go
// Tests for HTML‐based plugin discovery functions.

package scanner

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func sortedSlice(ss []string) []string {
	s := append([]string(nil), ss...)
	sort.Strings(s)
	return s
}

func TestExtractSlugsFromReader(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		wantSlugs []string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := make(map[string]struct{})
			err := extractSlugsFromReader(strings.NewReader(tt.html), dest)
			if err != nil {
				t.Fatalf("extractSlugsFromReader returned error: %v", err)
			}

			var got []string
			for slug := range dest {
				got = append(got, slug)
			}
			got = sortedSlice(got)
			want := sortedSlice(tt.wantSlugs)

			if !reflect.DeepEqual(got, want) {
				t.Errorf("extractSlugsFromReader = %v, want %v", got, want)
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

	slugs, err := discoverPluginsFromHTML(ts.URL, nil)
	if err != nil {
		t.Fatalf("discoverPluginsFromHTML returned error: %v", err)
	}

	got := sortedSlice(slugs)
	want := sortedSlice([]string{"pluginX", "pluginY", "pluginZ"})

	if !reflect.DeepEqual(got, want) {
		t.Errorf("discoverPluginsFromHTML = %v, want %v", got, want)
	}
}
