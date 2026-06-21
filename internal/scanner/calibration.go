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
	"hash/fnv"

	"github.com/Chocapikk/wpprobe/internal/http"
)

// probeBodyCap is how many bytes of a response body we fingerprint. The head of
// a WordPress "not found" page (doctype, <head>, theme markup) is identical
// whatever path was requested, so a small prefix is enough to recognise it,
// while a real plugin file (an empty PHP `exit`, or readme.txt content) hashes
// differently. Capping the read also avoids downloading a full 404 page per probe.
const probeBodyCap = 2048

// responseSig classifies an HTTP response by status code plus a hash of its body
// prefix. Two "not found" responses share a signature; a served or executed
// plugin file produces a different one.
type responseSig struct {
	status   int
	bodyHash uint64
}

func signature(status int, body string) responseSig {
	h := fnv.New64a()
	_, _ = h.Write([]byte(body))
	return responseSig{status: status, bodyHash: h.Sum64()}
}

// Calibrator learns, per target, what a request for a NON-existent plugin file
// looks like. Detection then flags a probe as a hit only when its response does
// not match that learned "miss" baseline. This is what makes file probing work
// regardless of the web server and its config:
//
//   - Apache routes any missing path to index.php -> WordPress answers with a
//     canonical 301 to "<path>/" (or a 404).
//   - nginx (try_files ... =404 in the php location) answers a missing .php with
//     a hard 404, but a missing readme.txt with the same WordPress 301.
//   - a hardened plugin (.htaccess deny) answers 403 for files that DO exist.
//   - a soft-404 host answers 200 + the same page for everything.
//
// In every case the response for a file that exists differs from the calibrated
// miss, so we never hardcode "200 = found".
type Calibrator struct {
	// missSigs are exact (status, bodyHash) shapes seen for absent paths.
	missSigs map[responseSig]struct{}
	// missStatusOnly holds statuses whose body varies per request (e.g. a 404
	// page that echoes the requested path); for those we match on status alone.
	missStatusOnly map[int]struct{}
	available      bool
}

// calibrationPaths are random, almost-certainly-absent plugin paths. Two
// distinct slugs are used so we can tell a stable miss page from one that
// echoes the requested path. Both file types are covered because a missing
// .php and a missing static file can behave differently (see nginx above).
var calibrationPaths = []string{
	"wpprobe-calib-a9f3e1d7/wpprobe-calib-a9f3e1d7.php",
	"wpprobe-calib-a9f3e1d7/readme.txt",
	"wpprobe-calib-7c02bd54/index.php",
	"wpprobe-calib-7c02bd54/readme.txt",
}

// NewCalibrator probes the target with the known-absent paths and records the
// resulting response signatures as the miss baseline.
func NewCalibrator(ctx context.Context, client *http.HTTPClientManager, target string) *Calibrator {
	c := &Calibrator{
		missSigs:       make(map[responseSig]struct{}, len(calibrationPaths)),
		missStatusOnly: make(map[int]struct{}),
	}
	base := target + "/wp-content/plugins/"
	bodiesByStatus := make(map[int]map[uint64]struct{})

	for _, p := range calibrationPaths {
		select {
		case <-ctx.Done():
			return c
		default:
		}
		status, body, err := client.ProbeNoRedirect(ctx, base+p, probeBodyCap)
		if err != nil {
			continue
		}
		c.available = true
		sig := signature(status, body)
		c.missSigs[sig] = struct{}{}
		if bodiesByStatus[status] == nil {
			bodiesByStatus[status] = make(map[uint64]struct{})
		}
		bodiesByStatus[status][sig.bodyHash] = struct{}{}
	}

	// If a status produced more than one distinct body across the two slugs, its
	// body is path-dependent (it echoes the request), so the exact hash is
	// useless: match that status on the status code alone.
	for status, hashes := range bodiesByStatus {
		if len(hashes) > 1 {
			c.missStatusOnly[status] = struct{}{}
		}
	}
	return c
}

// IsInstalled reports whether a probe response indicates the file exists on
// disk, i.e. its signature does not match any calibrated miss.
func (c *Calibrator) IsInstalled(status int, body string) bool {
	if !c.available {
		// Calibration failed (e.g. target unreachable during calibration): fall
		// back to "served or hardened" — a file that is served (200) or exists
		// but is access-denied (403).
		return status == 200 || status == 403
	}
	if _, ok := c.missStatusOnly[status]; ok {
		return false
	}
	_, isMiss := c.missSigs[signature(status, body)]
	return !isMiss
}
