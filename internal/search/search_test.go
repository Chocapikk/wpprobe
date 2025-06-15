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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package search_test

import (
	"strings"
	"testing"

	"github.com/Chocapikk/wpprobe/internal/search"
	"github.com/Chocapikk/wpprobe/internal/wordfence"
	"github.com/charmbracelet/lipgloss/tree"
)

func makeVuln(cve, slug, severity, auth string) wordfence.Vulnerability {
	return wordfence.Vulnerability{
		CVE:             cve,
		Slug:            slug,
		Severity:        severity,
		CVELink:         "https://cve.org/CVERecord?id=" + cve,
		AffectedVersion: "*",
		AuthType:        auth,
		CVSSScore:       5.0,
	}
}

func TestBuildTreeStructure(t *testing.T) {
	root := tree.Root("root")
	byPlugin := map[string][]wordfence.Vulnerability{
		"x": {makeVuln("CVE-9", "x", "low", "Auth")},
	}

	search.BuildTree(root, byPlugin, true)

	out := root.String()

	if !strings.Contains(out, "x  C:0 H:0 M:0 L:1 U:0") {
		t.Errorf("tree output missing summary node: %s", out)
	}
	if !strings.Contains(out, "Download: https://wordpress.org/plugins/x/") {
		t.Errorf("tree output missing download link: %s", out)
	}
	if !strings.Contains(out, "CVE-9") {
		t.Errorf("tree output missing CVE entry: %s", out)
	}
}
