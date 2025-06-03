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
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Chocapikk/wpprobe/internal/utils"
	"golang.org/x/net/html"
)

func discoverPluginsFromHTML(target string, headers []string) ([]string, error) {
	normalized := utils.NormalizeURL(target) + "/"

	client := utils.NewHTTPClient(10*time.Second, headers)
	htmlContent, err := client.Get(normalized)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch homepage %s: %w", normalized, err)
	}

	slugsSet := make(map[string]struct{})
	if err := extractSlugsFromReader(strings.NewReader(htmlContent), slugsSet); err != nil {
		return nil, fmt.Errorf("failed to parse HTML %s: %w", normalized, err)
	}

	var slugs []string
	for slug := range slugsSet {
		slugs = append(slugs, slug)
	}
	return slugs, nil
}

func extractSlugsFromReader(r io.Reader, dest map[string]struct{}) error {
	z := html.NewTokenizer(r)

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if z.Err() == io.EOF {
				return nil
			}
			return z.Err()

		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			for _, attr := range t.Attr {
				val := strings.TrimSpace(attr.Val)
				if val == "" {
					continue
				}
				if attr.Key == "href" || attr.Key == "src" {
					if idx := strings.Index(val, "/wp-content/plugins/"); idx != -1 {
						rest := val[idx+len("/wp-content/plugins/"):]
						parts := strings.SplitN(rest, "/", 2)
						if len(parts) > 0 && parts[0] != "" {
							dest[parts[0]] = struct{}{}
						}
					}
				}
			}
		}
	}
}
