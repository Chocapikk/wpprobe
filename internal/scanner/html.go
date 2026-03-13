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
	"io"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/Chocapikk/wpprobe/internal/http"
)

// isValidSlug checks if s matches (?i)[a-z][a-z0-9_-]* without regex overhead.
func isValidSlug(s string) bool {
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

func discoverPluginsFromHTML(ctx context.Context, target string, cfg http.Config) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	normalized := http.NormalizeURL(target)
	client := cfg.NewClient(5 * time.Second)

	slugsSet := make(map[string]struct{})

	if body, err := client.GetWithContext(ctx, normalized+"/"); err == nil {
		_ = extractSlugsFromReader(strings.NewReader(body), slugsSet)
	}

	// Check context between requests
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if body, err := client.GetWithContext(ctx, normalized+"/feed/"); err == nil {
		_ = extractSlugsFromReader(strings.NewReader(body), slugsSet)
	}

	// Check context between requests
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if body, err := client.GetWithContext(ctx, normalized+"/wp-content/uploads/"); err == nil {
		_ = extractSlugsFromReader(strings.NewReader(body), slugsSet)
	}

	slugs := make([]string, 0, len(slugsSet))
	for slug := range slugsSet {
		slugs = append(slugs, slug)
	}
	return slugs, nil
}

// extractSlugFromPath finds prefix (e.g. "wp-content/plugins/") in val and extracts the slug after it.
func extractSlugFromPath(val, prefix string, dest map[string]struct{}) {
	search := val
	for {
		idx := strings.Index(search, prefix)
		if idx < 0 {
			return
		}
		after := search[idx+len(prefix):]
		// Extract slug up to next "/" or end of string
		end := strings.IndexByte(after, '/')
		var slug string
		if end < 0 {
			slug = after
		} else {
			slug = after[:end]
		}
		if isValidSlug(slug) {
			dest[slug] = struct{}{}
		}
		// Continue searching after this match
		search = after
	}
}

func extractSlugsFromReader(r io.Reader, dest map[string]struct{}) error {
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				return nil
			}
			return z.Err()
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		tok := z.Token()
		for _, attr := range tok.Attr {
			val := attr.Val
			// Use index-based search to avoid strings.Split allocation
			extractSlugFromPath(val, "wp-content/plugins/", dest)
			extractSlugFromPath(val, "wp-content/uploads/", dest)
		}
	}
}
