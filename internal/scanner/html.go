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
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/Chocapikk/wpprobe/internal/http"
)

func discoverPluginsFromHTML(target string, headers []string, proxyURL string, rps int) ([]string, error) {
	normalized := http.NormalizeURL(target)
	client := http.NewHTTPClient(10*time.Second, headers, proxyURL, rps)

	slugsSet := make(map[string]struct{})

	if body, err := client.Get(normalized + "/"); err == nil {
		_ = extractSlugsFromReader(strings.NewReader(body), slugsSet)
	}

	if body, err := client.Get(normalized + "/wp-content/uploads/"); err == nil {
		_ = extractSlugsFromReader(strings.NewReader(body), slugsSet)
	}

	var slugs []string
	for slug := range slugsSet {
		slugs = append(slugs, slug)
	}
	return slugs, nil
}

func extractSlugsFromReader(r io.Reader, dest map[string]struct{}) error {
	var slugPattern = regexp.MustCompile(`(?i)^[a-z][a-z0-9_-]*$`)

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
			val := strings.TrimSpace(attr.Val)
			if val == "" {
				continue
			}
			parts := strings.Split(val, "/")
			for i := 0; i < len(parts)-2; i++ {
				if parts[i] == "wp-content" &&
					(parts[i+1] == "plugins" || parts[i+1] == "uploads") {
					slug := parts[i+2]
					if slugPattern.MatchString(slug) {
						dest[slug] = struct{}{}
					}
				}
			}
		}
	}
}
