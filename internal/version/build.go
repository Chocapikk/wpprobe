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
	"runtime/debug"
	"strings"
)

// devVersion is what Version holds when no release version was linked in.
const devVersion = "dev"

// Info describes the running build.
type Info struct {
	// Display is the short form shown in the banner.
	Display string
	// Comparable is the form checked against the published releases. It is
	// empty when the build carries no version the toolchain could derive, in
	// which case no comparison should be attempted at all.
	Comparable string
	// Release reports whether the version was linked in at build time, which
	// only the release pipeline does. A build from source is not a release even
	// when its derived version is perfectly comparable.
	Release bool
}

// Current describes the running binary.
//
// A release binary carries its version through -ldflags and needs nothing else.
// A build from source does not, and used to report itself as "dev", which the
// semver comparison could not parse, so every such build was labelled outdated
// and pointed at `wpprobe update` - which would have replaced it with an older
// release binary. The Go toolchain already embeds a usable version in both
// source install paths, so that is what fills the gap.
func Current() Info {
	if Version != "" && Version != devVersion {
		return Info{Display: Version, Comparable: Version, Release: true}
	}
	if moduleVersion, ok := readModuleVersion(); ok {
		return Info{Display: shortVersion(moduleVersion), Comparable: moduleVersion}
	}
	return Info{Display: devVersion}
}

// readModuleVersion is swapped in tests, which run from a binary the toolchain
// stamps differently from a built command.
var readModuleVersion = embeddedModuleVersion

// embeddedModuleVersion returns the version the toolchain recorded in the
// binary. `go install <module>@<version>` records the tag itself; `go build`
// inside a checkout records a pseudo-version derived from the commit, which
// sorts above the release it descends from, so a checkout ahead of the latest
// tag is correctly seen as not outdated. "(devel)" means the source had no
// version control information to derive anything from, and is the one case
// left with nothing to compare.
func embeddedModuleVersion() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	moduleVersion := info.Main.Version
	if moduleVersion == "" || moduleVersion == "(devel)" {
		return "", false
	}
	return moduleVersion, true
}

// shortVersion turns a pseudo-version into something that fits a banner:
// v0.12.6-0.20260818043543-4246323980b5+dirty becomes v0.12.6-dev.4246323980b5,
// with a -dirty suffix kept when the working tree had uncommitted changes. A
// plain tag is returned untouched.
func shortVersion(moduleVersion string) string {
	base, revision, isPseudo := strings.Cut(moduleVersion, "-0.")
	if !isPseudo {
		return moduleVersion
	}
	dirty := strings.Contains(revision, "+dirty")
	// A pseudo-version's suffix is <timestamp>-<commit>[+metadata]; the commit
	// is the part worth showing.
	if _, commit, ok := strings.Cut(revision, "-"); ok {
		revision = commit
	}
	if index := strings.IndexByte(revision, '+'); index >= 0 {
		revision = revision[:index]
	}
	short := base + "-dev." + revision
	if dirty {
		short += "-dirty"
	}
	return short
}
