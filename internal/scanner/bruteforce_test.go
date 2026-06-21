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

import "testing"

// candidateFiles must use the curated fingerprint when present, and otherwise
// reconstruct a generic set from the slug, so a plain slug list keeps working.
func TestCandidateFiles(t *testing.T) {
	fingerprints := map[string][]string{
		"woocommerce": {"woocommerce.php", "readme.txt"},
	}

	if got := candidateFiles("woocommerce", fingerprints); !slicesEqual(got, []string{"woocommerce.php", "readme.txt"}) {
		t.Errorf("curated slug: got %v", got)
	}

	want := []string{"some-obscure-plugin.php", "readme.txt", "index.php"}
	if got := candidateFiles("some-obscure-plugin", fingerprints); !slicesEqual(got, want) {
		t.Errorf("generic reconstruction: got %v, want %v", got, want)
	}

	if got := candidateFiles("anything", nil); !slicesEqual(got, []string{"anything.php", "readme.txt", "index.php"}) {
		t.Errorf("nil fingerprints: got %v", got)
	}
}
