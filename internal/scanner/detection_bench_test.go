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
	"strconv"
	"testing"
)

func BenchmarkDetectPlugins_Small(b *testing.B) {
	detectedEndpoints := []string{
		"/wp/v2/plugins",
		"/wp/v2/users",
		"/woocommerce/v1/products",
		"/elementor/v1/templates",
	}
	pluginEndpoints := map[string][]string{
		"woocommerce": {"/woocommerce/v1/products", "/woocommerce/v1/orders"},
		"elementor":  {"/elementor/v1/templates", "/elementor/v1/pages"},
		"jetpack":     {"/jetpack/v4/site"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectPlugins(detectedEndpoints, pluginEndpoints)
	}
}

func BenchmarkDetectPlugins_Medium(b *testing.B) {
	detectedEndpoints := make([]string, 100)
	for i := 0; i < 100; i++ {
		detectedEndpoints[i] = "/wp/v2/endpoint" + strconv.Itoa(i)
	}

	pluginEndpoints := make(map[string][]string, 50)
	for i := 0; i < 50; i++ {
		pluginEndpoints["plugin"+strconv.Itoa(i)] = []string{
			"/wp/v2/endpoint" + strconv.Itoa(i),
			"/wp/v2/endpoint" + strconv.Itoa(i+50),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectPlugins(detectedEndpoints, pluginEndpoints)
	}
}

func BenchmarkDetectPlugins_Large(b *testing.B) {
	detectedEndpoints := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		detectedEndpoints[i] = "/wp/v2/endpoint" + strconv.Itoa(i)
	}

	pluginEndpoints := make(map[string][]string, 500)
	for i := 0; i < 500; i++ {
		routes := make([]string, 5)
		for j := 0; j < 5; j++ {
			routes[j] = "/wp/v2/endpoint" + strconv.Itoa(i*5+j)
		}
		pluginEndpoints["plugin"+strconv.Itoa(i)] = routes
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectPlugins(detectedEndpoints, pluginEndpoints)
	}
}

