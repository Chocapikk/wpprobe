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

package version

import (
	"strings"
	"testing"

	"github.com/Masterminds/semver"
)

// A linked-in version is taken as is and marks the build as a release.
func TestCurrentWithLinkedVersion(t *testing.T) {
	original := Version
	defer func() { Version = original }()

	Version = "v1.2.3"
	build := Current()
	if build.Display != "v1.2.3" || build.Comparable != "v1.2.3" {
		t.Errorf("Current() = %+v, want v1.2.3 in both fields", build)
	}
	if !build.Release {
		t.Error("a linked-in version must mark the build as a release")
	}
}

// Without a linked-in version the toolchain's module version fills the gap.
// This is the case that used to report "dev" and get labelled outdated.
func TestCurrentFallsBackToModuleVersion(t *testing.T) {
	originalVersion, originalReader := Version, readModuleVersion
	defer func() { Version, readModuleVersion = originalVersion, originalReader }()

	Version = devVersion
	readModuleVersion = func() (string, bool) {
		return "v0.12.6-0.20260818043543-4246323980b5+dirty", true
	}

	build := Current()
	if build.Release {
		t.Error("a build from source must not be reported as a release")
	}
	if build.Comparable != "v0.12.6-0.20260818043543-4246323980b5+dirty" {
		t.Errorf("Comparable = %q, want the module version verbatim", build.Comparable)
	}
	if build.Display != "v0.12.6-dev.4246323980b5-dirty" {
		t.Errorf("Display = %q, want the short form", build.Display)
	}
}

// "(devel)" and an empty version are the only cases with nothing to compare, and
// they must stay that way rather than being guessed at.
func TestCurrentWithoutAnyVersion(t *testing.T) {
	originalVersion, originalReader := Version, readModuleVersion
	defer func() { Version, readModuleVersion = originalVersion, originalReader }()

	Version = devVersion
	readModuleVersion = func() (string, bool) { return "", false }

	build := Current()
	if build.Display != devVersion {
		t.Errorf("Display = %q, want %q", build.Display, devVersion)
	}
	if build.Comparable != "" {
		t.Errorf("Comparable = %q, want empty so no release comparison is attempted", build.Comparable)
	}
	if build.Release {
		t.Error("a build with no version must not be reported as a release")
	}
}

// embeddedModuleVersion itself must reject the placeholders it can be handed.
func TestEmbeddedModuleVersionRejectsPlaceholders(t *testing.T) {
	if version, ok := embeddedModuleVersion(); ok && (version == "" || version == "(devel)") {
		t.Errorf("embeddedModuleVersion() accepted the placeholder %q", version)
	}
}

// The whole point of the fallback: the derived version has to be something the
// release comparison can actually parse, and a checkout ahead of a tag has to
// compare as ahead rather than as outdated.
func TestPseudoVersionComparesAheadOfItsTag(t *testing.T) {
	const pseudo = "v0.12.6-0.20260818043543-4246323980b5+dirty"

	current, err := semver.NewVersion(strings.TrimPrefix(pseudo, "v"))
	if err != nil {
		t.Fatalf("a pseudo-version must be parseable by the release comparison: %v", err)
	}
	tag, err := semver.NewVersion("0.12.5")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if current.Compare(tag) <= 0 {
		t.Errorf("%s compared %d against its own tag, want ahead", pseudo, current.Compare(tag))
	}
}

func TestShortVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain tag is untouched", "v0.12.5", "v0.12.5"},
		{
			"pseudo-version keeps base and commit",
			"v0.12.6-0.20260818043543-4246323980b5",
			"v0.12.6-dev.4246323980b5",
		},
		{
			"dirty tree is called out",
			"v0.12.6-0.20260818043543-4246323980b5+dirty",
			"v0.12.6-dev.4246323980b5-dirty",
		},
		{"prerelease tag is untouched", "v1.0.0-rc1", "v1.0.0-rc1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shortVersion(tt.input); got != tt.want {
				t.Errorf("shortVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
