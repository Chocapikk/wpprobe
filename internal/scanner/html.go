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
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/Chocapikk/wpprobe/internal/http"
)

// isValidSlug checks if s matches (?i)[a-z][a-z0-9_-]* without regex overhead.
// It takes bytes because the caller reads them straight out of the tokenizer's
// buffer, where turning a candidate into a string just to reject it would be
// the bulk of the work.
func isValidSlug(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0] | 0x20 // lowercase
	if c < 'a' || c > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c = s[i] | 0x20
		if (c >= 'a' && c <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '_' || s[i] == '-' {
			continue
		}
		return false
	}
	return true
}

// HTMLDiscoveryResult holds both plugins and themes discovered from HTML.
type HTMLDiscoveryResult struct {
	Plugins []string
	Themes  []string
}

func discoverFromHTML(ctx context.Context, target string, cfg http.Config) (HTMLDiscoveryResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-ctx.Done():
		return HTMLDiscoveryResult{}, ctx.Err()
	default:
	}

	normalized := http.NormalizeURL(target)
	client := cfg.NewClient(5 * time.Second)

	pluginsSet := make(map[string]struct{})
	themesSet := make(map[string]struct{})

	pages := []string{"/", "/feed/", "/wp-content/uploads/"}
	for _, page := range pages {
		select {
		case <-ctx.Done():
			return HTMLDiscoveryResult{}, ctx.Err()
		default:
		}
		if body, err := client.GetWithContext(ctx, normalized+page); err == nil {
			_ = extractSlugsFromReader(strings.NewReader(body), pluginsSet, themesSet)
		}
	}

	plugins := make([]string, 0, len(pluginsSet))
	for slug := range pluginsSet {
		plugins = append(plugins, slug)
	}
	themes := make([]string, 0, len(themesSet))
	for slug := range themesSet {
		themes = append(themes, slug)
	}
	return HTMLDiscoveryResult{Plugins: plugins, Themes: themes}, nil
}

// discoverPluginsFromHTML is a compatibility wrapper that returns only plugins.
func discoverPluginsFromHTML(ctx context.Context, target string, cfg http.Config) ([]string, error) {
	result, err := discoverFromHTML(ctx, target, cfg)
	return result.Plugins, err
}

var (
	wpContentMarker = []byte("wp-content/")
	pluginsPrefix   = []byte("wp-content/plugins/")
	uploadsPrefix   = []byte("wp-content/uploads/")
	themesPrefix    = []byte("wp-content/themes/")
)

// extractSlugFromPath finds prefix (e.g. "wp-content/plugins/") in val and extracts the slug after it.
// A string is only built for a candidate that passes validation and is being
// stored, so a page full of unrelated markup allocates nothing here.
func extractSlugFromPath(val, prefix []byte, dest map[string]struct{}) {
	search := val
	for {
		idx := bytes.Index(search, prefix)
		if idx < 0 {
			return
		}
		after := search[idx+len(prefix):]
		// Extract slug up to next "/" or end of string
		slug := after
		if end := bytes.IndexByte(after, '/'); end >= 0 {
			slug = after[:end]
		}
		if isValidSlug(slug) {
			dest[string(slug)] = struct{}{}
		}
		// Continue searching after this match
		search = after
	}
}

// extractSlugsFrom scans one attribute value or text run for all three
// locations. The single marker check up front is what makes it cheap: most of a
// page mentions wp-content nowhere, and rejecting it once beats three separate
// searches.
func extractSlugsFrom(val []byte, pluginDest, themeDest map[string]struct{}) {
	if !bytes.Contains(val, wpContentMarker) {
		return
	}
	extractSlugFromPath(val, pluginsPrefix, pluginDest)
	extractSlugFromPath(val, uploadsPrefix, pluginDest)
	extractSlugFromPath(val, themesPrefix, themeDest)
}

func extractSlugsFromReader(r io.Reader, pluginDest, themeDest map[string]struct{}) error {
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				return nil
			}
			return z.Err()
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			// TagAttr walks the attributes in the tokenizer's own buffer.
			// z.Token() would allocate a Token and copy every name and value on
			// every tag, whether or not the tag mentions wp-content at all.
			_, hasAttr := z.TagName()
			for hasAttr {
				var val []byte
				_, val, hasAttr = z.TagAttr()
				extractSlugsFrom(val, pluginDest, themeDest)
			}
		case html.TextToken:
			extractSlugsFrom(z.Text(), pluginDest, themeDest)
		}
	}
}
