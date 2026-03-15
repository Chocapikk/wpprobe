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
	"strings"
	"testing"
)

func BenchmarkIsValidSlug(b *testing.B) {
	slugs := []string{
		"woocommerce",
		"elementor-pro",
		"wp_mail_smtp",
		"",
		"123invalid",
		"a",
		"really-long-plugin-name-with-many-dashes-and-stuff",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range slugs {
			_ = isValidSlug(s)
		}
	}
}

func BenchmarkExtractSlugFromPath(b *testing.B) {
	vals := []string{
		"https://example.com/wp-content/plugins/woocommerce/assets/style.css",
		"https://example.com/wp-content/plugins/elementor/css/frontend.min.css",
		"https://example.com/wp-content/uploads/2024/01/image.png",
		"https://example.com/some/other/path/without/plugins",
		"/wp-content/plugins/contact-form-7/includes/js/scripts.js",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dest := make(map[string]struct{})
		for _, v := range vals {
			extractSlugFromPath(v, "wp-content/plugins/", dest)
		}
	}
}

func buildHTML(pluginCount int) string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head>")
	for i := 0; i < pluginCount; i++ {
		slug := fmt.Sprintf("plugin-%d", i)
		sb.WriteString(fmt.Sprintf(
			`<link rel="stylesheet" href="https://example.com/wp-content/plugins/%s/css/style.css">`,
			slug,
		))
		sb.WriteString(fmt.Sprintf(
			`<script src="https://example.com/wp-content/plugins/%s/js/main.js"></script>`,
			slug,
		))
	}
	sb.WriteString("</head><body>")
	// Add some noise
	for i := 0; i < pluginCount; i++ {
		sb.WriteString(fmt.Sprintf(`<div class="widget-%d"><p>Content %d</p></div>`, i, i))
	}
	sb.WriteString("</body></html>")
	return sb.String()
}

func BenchmarkExtractSlugsFromReader_Small(b *testing.B) {
	html := buildHTML(5)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dest := make(map[string]struct{})
		_ = extractSlugsFromReader(strings.NewReader(html), dest)
	}
}

func BenchmarkExtractSlugsFromReader_Medium(b *testing.B) {
	html := buildHTML(50)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dest := make(map[string]struct{})
		_ = extractSlugsFromReader(strings.NewReader(html), dest)
	}
}

func BenchmarkExtractSlugsFromReader_Large(b *testing.B) {
	html := buildHTML(200)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dest := make(map[string]struct{})
		_ = extractSlugsFromReader(strings.NewReader(html), dest)
	}
}

func BenchmarkExtractSlugsFromReader_RealWorldPage(b *testing.B) {
	// Simulate a realistic WP page with mixed content
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head>
<meta charset="utf-8">
<title>My WordPress Site</title>
<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css">
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css">
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css">
<link rel="stylesheet" href="/wp-content/plugins/wordfence/css/main.css">
<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css">
<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js"></script>
<script src="/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js"></script>
<script src="/wp-content/plugins/jetpack/modules/widgets.js"></script>
<script src="/wp-includes/js/jquery/jquery.min.js"></script>
</head><body>
<div class="header"><img src="/wp-content/uploads/2024/01/logo.png"></div>
<div class="content">`)
	for i := 0; i < 20; i++ {
		sb.WriteString(fmt.Sprintf(`<article class="post-%d">
<h2>Blog Post %d</h2>
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
<img src="/wp-content/uploads/2024/01/image-%d.jpg">
</article>`, i, i, i))
	}
	sb.WriteString(`</div>
<div class="sidebar">
<div class="widget" id="recent-posts"><ul><li>Post 1</li><li>Post 2</li></ul></div>
</div>
</body></html>`)
	html := sb.String()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dest := make(map[string]struct{})
		_ = extractSlugsFromReader(strings.NewReader(html), dest)
	}
}

func BenchmarkExtractSlugsFromReader_NoPlugins(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><title>Plain</title></head><body>")
	for i := 0; i < 100; i++ {
		sb.WriteString(fmt.Sprintf(`<div><p>Paragraph %d with no plugin references.</p></div>`, i))
	}
	sb.WriteString("</body></html>")
	html := sb.String()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dest := make(map[string]struct{})
		_ = extractSlugsFromReader(strings.NewReader(html), dest)
	}
}
