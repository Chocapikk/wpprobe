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

	"github.com/Chocapikk/wpprobe/internal/http"
)

// probeBodyCap is how many bytes of a response body we fingerprint. The head of
// a WordPress "not found" page (doctype, <head>, theme markup) is identical
// whatever path was requested, so a small prefix is enough to recognise it,
// while a real plugin file (an empty PHP `exit`, or readme.txt content) hashes
// differently. Capping the read also avoids downloading a full 404 page per probe.
const probeBodyCap = 2048

// responseSig classifies an HTTP response by status code plus a hash of its
// normalized body prefix. Two "not found" responses share a signature; a served
// or executed plugin file produces a different one.
type responseSig struct {
	status   int
	bodyHash uint64
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// matchFold reports whether s, starting at pos, begins with token (token must
// already be lowercase), comparing ASCII case-insensitively.
func matchFold(s string, pos int, token string) bool {
	if pos+len(token) > len(s) {
		return false
	}
	for i := 0; i < len(token); i++ {
		if asciiLower(s[pos+i]) != token[i] {
			return false
		}
	}
	return true
}

// indexFold returns the first index >= pos where token (lowercase) occurs in s,
// case-insensitively, or -1.
func indexFold(s string, pos int, token string) int {
	for ; pos+len(token) <= len(s); pos++ {
		if matchFold(s, pos, token) {
			return pos
		}
	}
	return -1
}

// FNV-1a 64-bit constants. The hash is inlined so the normalized bytes can be
// streamed straight in, without ever materializing a normalized string.
const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// normalizedHash returns the FNV-1a 64-bit hash of the body with the parts that
// can legitimately vary between two identical requests neutralized, so a dynamic
// "not found" page is not mistaken for a served file: inline <script> blocks and
// HTML comments are dropped, runs of digits (timestamps, cache busters, numeric
// IDs) collapse to a single '#', and whitespace runs collapse to one space with
// leading/trailing trimmed. This is the same idea WPScan uses (stripping scripts
// and comments before hashing the 404 page), extended to also neutralize numeric
// volatility. Residual per-request tokens (e.g. CSP nonces) are caught
// separately: they make the calibration probes disagree, marking the status as
// status-only.
//
// It runs in a single pass and allocates NOTHING: no intermediate normalized
// string is built, the bytes are folded straight into the hash. A
// strings.Builder + regex version was ~18x slower at 26 allocations; this path
// runs once per probe on soft-404 hosts.
func normalizedHash(s string) uint64 {
	hash := uint64(fnvOffset64)
	mix := func(c byte) {
		hash ^= uint64(c)
		hash *= fnvPrime64
	}

	emitted, pendingSpace, lastDigit := false, false, false
	for i, n := 0, len(s); i < n; {
		c := s[i]
		if c == '<' {
			if matchFold(s, i, "<script") {
				if end := indexFold(s, i+7, "</script>"); end >= 0 {
					i = end + len("</script>")
				} else {
					i = n
				}
				lastDigit = false
				continue
			}
			if matchFold(s, i, "<!--") {
				if end := indexFold(s, i+4, "-->"); end >= 0 {
					i = end + len("-->")
				} else {
					i = n
				}
				lastDigit = false
				continue
			}
		}

		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			pendingSpace = emitted // ignore leading whitespace; trailing never flushes
			lastDigit = false
		case c >= '0' && c <= '9':
			if pendingSpace {
				mix(' ')
				pendingSpace = false
			}
			if !lastDigit {
				mix('#')
				emitted = true
			}
			lastDigit = true
		default:
			if pendingSpace {
				mix(' ')
				pendingSpace = false
			}
			mix(c)
			emitted, lastDigit = true, false
		}
		i++
	}

	return hash
}

func signature(status int, body string) responseSig {
	return responseSig{status: status, bodyHash: normalizedHash(body)}
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
	// missStatuses are the status codes seen for absent paths. A probe whose
	// status is not in here was served/executed and is therefore a hit, decided
	// without touching the body (the common 200/403 hit vs 301/404 miss case).
	missStatuses map[int]struct{}
	// missSigs are exact (status, normalized-bodyHash) shapes seen for absent
	// paths. Only consulted for ambiguous statuses (see bodyAmbiguous).
	missSigs map[responseSig]struct{}
	// missStatusOnly holds statuses whose body varies per request (e.g. a 404
	// page that echoes the requested path); for those we match on status alone.
	missStatusOnly map[int]struct{}
	available      bool
}

// bodyAmbiguous reports whether a "not found" status could also be returned by a
// file that exists. Only these need a body comparison: a served file answers
// 200, a hardened one 403, and a fatal-on-direct-access one 500. Any other miss
// status (301, 302, 404, ...) is never produced by an existing file, so the
// status alone settles it and the body is never hashed.
func bodyAmbiguous(status int) bool {
	return status == 200 || status == 403 || status == 500
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
		missStatuses:   make(map[int]struct{}),
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
		c.missStatuses[status] = struct{}{}
		// Only ambiguous statuses ever need the body hash; skip the work otherwise.
		if !bodyAmbiguous(status) {
			continue
		}
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
	// Fast path: a status the server never used for "not found" means the file
	// was served or executed. No body work for the common 200/403 hit.
	if _, isMiss := c.missStatuses[status]; !isMiss {
		return true
	}
	// The status is a "not found" status. If a served file could not have
	// produced it, it is unambiguously a miss (no body hash).
	if !bodyAmbiguous(status) {
		return false
	}
	if _, ok := c.missStatusOnly[status]; ok {
		return false
	}
	_, isMiss := c.missSigs[signature(status, body)]
	return !isMiss
}
