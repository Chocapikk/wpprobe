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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Chocapikk/wpprobe/internal/http"
	"github.com/Chocapikk/wpprobe/internal/logger"
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

func asciiLower(character byte) byte {
	if character >= 'A' && character <= 'Z' {
		return character + 32
	}
	return character
}

// matchFold reports whether s, starting at pos, begins with token (token must
// already be lowercase), comparing ASCII case-insensitively.
func matchFold(input string, position int, token string) bool {
	if position+len(token) > len(input) {
		return false
	}
	for tokenIndex := 0; tokenIndex < len(token); tokenIndex++ {
		if asciiLower(input[position+tokenIndex]) != token[tokenIndex] {
			return false
		}
	}
	return true
}

// indexFold returns the first index >= pos where token (lowercase) occurs in s,
// case-insensitively, or -1.
func indexFold(input string, position int, token string) int {
	for ; position+len(token) <= len(input); position++ {
		if matchFold(input, position, token) {
			return position
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
func normalizedHash(input string) uint64 {
	hash := uint64(fnvOffset64)
	mix := func(character byte) {
		hash ^= uint64(character)
		hash *= fnvPrime64
	}

	emitted, pendingSpace, lastDigit := false, false, false
	for position, inputLength := 0, len(input); position < inputLength; {
		character := input[position]
		if character == '<' {
			if matchFold(input, position, "<script") {
				if end := indexFold(input, position+7, "</script>"); end >= 0 {
					position = end + len("</script>")
				} else {
					position = inputLength
				}
				lastDigit = false
				continue
			}
			if matchFold(input, position, "<!--") {
				if end := indexFold(input, position+4, "-->"); end >= 0 {
					position = end + len("-->")
				} else {
					position = inputLength
				}
				lastDigit = false
				continue
			}
		}

		switch {
		case character == ' ' || character == '\t' || character == '\n' || character == '\r' || character == '\f' || character == '\v':
			pendingSpace = emitted // ignore leading whitespace; trailing never flushes
			lastDigit = false
		case character >= '0' && character <= '9':
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
			mix(character)
			emitted, lastDigit = true, false
		}
		position++
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
	// missBodies holds the distinct ambiguous response bodies collected during
	// calibration. Near-matches are treated as misses, which catches fabricated
	// readmes whose slug or fake version changes on every request. Bodies are
	// deduplicated by their normalized signature, so a template that only varies
	// in its digits contributes a single entry.
	missBodies map[int][]string
	// fabricatesContent records that calibration was answered with a plausible
	// plugin readme (200 + "Stable tag:") for a slug that cannot exist. It is
	// informational: the suppression itself happens in IsInstalled, which
	// compares every probe against the calibrated bodies.
	fabricatesContent bool
	available         bool
}

// maxMissBodiesPerStatus caps how many distinct bodies are kept per status.
// IsInstalled compares every ambiguous probe against each of them, so an
// unbounded list would make a large brute-force run pay a similarity pass per
// stored body. Hosts that fabricate content answer with one template, so the
// deduplicated list is normally one or two entries.
const maxMissBodiesPerStatus = 5

const missBodySimilarityThreshold = 0.70

// bodySimilarity returns the Sørensen-Dice similarity of two response bodies.
// Tokens are compared as a multiset so small changes in paths, generated
// versions, timestamps, or ordering do not prevent a fabricated template from
// matching its calibration baseline.
func bodySimilarity(candidateBody, calibrationBody string) float64 {
	candidateTokens := strings.Fields(strings.ToLower(candidateBody))
	calibrationTokens := strings.Fields(strings.ToLower(calibrationBody))
	if len(candidateTokens) == 0 || len(calibrationTokens) == 0 {
		if len(candidateTokens) == len(calibrationTokens) {
			return 1
		}
		return 0
	}

	candidateTokenCounts := make(map[string]int, len(candidateTokens))
	for _, candidateToken := range candidateTokens {
		candidateTokenCounts[similarityToken(candidateToken)]++
	}

	commonTokenCount := 0
	for _, calibrationToken := range calibrationTokens {
		calibrationToken = similarityToken(calibrationToken)
		if candidateTokenCounts[calibrationToken] > 0 {
			commonTokenCount++
			candidateTokenCounts[calibrationToken]--
		}
	}

	return float64(2*commonTokenCount) / float64(len(candidateTokens)+len(calibrationTokens))
}

func similarityToken(token string) string {
	// Echoed request paths are the most common source of otherwise identical
	// soft-404 bodies differing during calibration.
	if strings.Contains(token, "/") {
		return "#path"
	}
	return token
}

// bodyAmbiguous reports whether a "not found" status could also be returned by a
// file that exists. Only these need a body comparison: a served file answers
// 200, a hardened one 403, and a fatal-on-direct-access one 500. Any other miss
// status (301, 302, 404, ...) is never produced by an existing file, so the
// status alone settles it and the body is never hashed.
func bodyAmbiguous(status int) bool {
	return status == 200 || status == 403 || status == 500
}

const calibrationAttempts = 5

// newCalibrationPaths returns the almost-certainly-absent plugin files used by
// the brute-force probe. Each path is calibrated independently because a web
// server or WAF may handle PHP files and readme filename casing differently.
func newCalibrationPaths() []string {
	slug := randomCalibrationSlug()
	return []string{
		slug + "/readme.txt",
		slug + "/Readme.txt",
		slug + "/" + slug + ".php",
	}
}

var calibrationFallbackCounter uint64

func randomCalibrationSlug() string {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		// A collision remains extremely unlikely even when the OS random source
		// is unavailable; the prefix itself is deliberately non-plugin-like.
		return fmt.Sprintf(
			"no-existing-plugin-%x-%x",
			normalizedHash(err.Error()),
			atomic.AddUint64(&calibrationFallbackCounter, 1),
		)
	}
	return "no-existing-plugin-" + hex.EncodeToString(random)
}

// NewCalibrator probes each known-absent candidate several times because a host
// may answer inconsistently: BitFire, for instance, fabricates a plausible
// readme for roughly four requests out of five and 404s the rest, so a single
// probe per path can miss the template entirely. Every attempt is recorded, at
// calibrationAttempts * len(newCalibrationPaths()) requests per target, so the
// baseline covers each response the host alternates between.
func NewCalibrator(ctx context.Context, client *http.HTTPClientManager, target string) *Calibrator {
	calibrator := &Calibrator{
		missStatuses: make(map[int]struct{}),
		missSigs:     make(map[responseSig]struct{}, len(newCalibrationPaths())),
		missBodies:   make(map[int][]string),
	}
	base := target + "/wp-content/plugins/"

	for _, calibrationPath := range newCalibrationPaths() {
		for attempt := 0; attempt < calibrationAttempts; attempt++ {
			select {
			case <-ctx.Done():
				return calibrator
			default:
			}
			status, body, err := client.ProbeNoRedirect(ctx, base+calibrationPath, probeBodyCap)
			if err != nil {
				continue
			}
			calibrator.available = true
			calibrator.missStatuses[status] = struct{}{}
			// Only ambiguous statuses ever need the body hash; skip the work otherwise.
			if !bodyAmbiguous(status) {
				continue
			}
			if status == 200 && strings.Contains(strings.ToLower(body), "stable tag:") {
				calibrator.fabricatesContent = true
			}
			calibrator.recordMissBody(status, body)
		}
	}
	return calibrator
}

// recordMissBody stores body as a miss baseline for status, skipping bodies
// whose normalized signature was already seen. A fabricated readme that only
// changes its version between requests normalizes to one signature, so the
// repeated calibration attempts cost nothing in stored state.
func (calibrator *Calibrator) recordMissBody(status int, body string) {
	sig := signature(status, body)
	if _, seen := calibrator.missSigs[sig]; seen {
		return
	}
	calibrator.missSigs[sig] = struct{}{}
	if len(calibrator.missBodies[status]) >= maxMissBodiesPerStatus {
		return
	}
	calibrator.missBodies[status] = append(calibrator.missBodies[status], body)
}

// IsInstalled reports whether a probe response indicates the file exists on
// disk, i.e. its signature does not match any calibrated miss.
func (calibrator *Calibrator) IsInstalled(status int, body string) bool {
	// A redirect is never a served file: the web server is rerouting the
	// request, not serving content from the plugin directory. This catches
	// hosts where calibration returns 404 but a WAF or reverse proxy returns
	// 301/302 for specific plugin slugs (issue #27).
	if status >= 300 && status < 400 {
		return false
	}
	if !calibrator.available {
		// Calibration failed (e.g. target unreachable during calibration): fall
		// back to "served or hardened" - a file that is served (200) or exists
		// but is access-denied (403).
		return status == 200 || status == 403
	}
	// Fast path: a status the server never used for "not found" means the file
	// was served or executed. No body work for the common 200/403 hit.
	if _, isMiss := calibrator.missStatuses[status]; !isMiss {
		return true
	}
	// The status is a "not found" status. If a served file could not have
	// produced it, it is unambiguously a miss (no body hash).
	if !bodyAmbiguous(status) {
		return false
	}
	if _, isMiss := calibrator.missSigs[signature(status, body)]; isMiss {
		return false
	}
	for _, missBody := range calibrator.missBodies[status] {
		if bodySimilarity(body, missBody) >= missBodySimilarityThreshold {
			return false
		}
	}
	return true
}

// FabricatesContent reports whether calibration was answered with a plausible
// plugin readme for a slug that cannot exist. Nothing keys off this beyond the
// user-facing warning: suppressing such a response is IsInstalled's job, which
// compares against the calibrated bodies with the response already in hand.
//
// Re-probing a detected plugin to confirm it is fabricated cannot work on these
// hosts. Any path the confirmation picks is either the real file (which does not
// match the template) or an absent one such as Readme.txt, which the host
// fabricates for exactly the same reason it fabricated during calibration - so
// the check reports every real plugin as fake.
func (calibrator *Calibrator) FabricatesContent() bool {
	return calibrator.fabricatesContent
}

func NewScanCalibrator(ctx context.Context, target string, opts ScanOptions) *Calibrator {
	if opts.Calibrator != nil {
		return opts.Calibrator
	}
	normalizedTarget := http.NormalizeURL(target)
	client := HTTPConfigFromOpts(opts).NewClient(10 * time.Second)
	return NewCalibrator(ctx, client, normalizedTarget)
}

// DisplayFabricatedContentWarning tells the user the target answers for slugs
// that cannot exist, so brute-force results on this host rest entirely on the
// calibrated baseline rather than on "the file was served".
func DisplayFabricatedContentWarning(progress Progress) {
	message := "The target serves plausible plugin content for slugs that do not exist; results matching the calibrated template are rejected."
	if progress != nil {
		_, _ = progress.Bprintln(logger.FormatWarning(message))
		return
	}
	logger.DefaultLogger.Logger.Println(logger.FormatWarning(message))
}
