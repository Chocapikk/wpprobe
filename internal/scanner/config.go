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
	"math"

	"github.com/Chocapikk/wpprobe/internal/file"
	"github.com/Chocapikk/wpprobe/internal/logger"
	"github.com/Chocapikk/wpprobe/internal/progress"
)

func loadTargets(opts ScanOptions) []string {
	if opts.File != "" {
		lines, err := file.ReadLines(opts.File)
		if err != nil {
			logger.DefaultLogger.Error("Failed to read file: " + err.Error())
			return nil
		}
		return lines
	}
	return []string{opts.URL}
}

func buildScanConfig(opts ScanOptions, targetCount int) scanConfig {
	totalThreads := opts.Threads
	if totalThreads < 1 {
		totalThreads = 1
	}

	if targetCount == 0 {
		targetCount = 1
	}

	// Optimize thread distribution to better utilize all available threads
	// For single target, use all threads
	if targetCount == 1 {
		return scanConfig{
			perSite:        totalThreads,
			siteConcurrent: 1,
			sem:            make(chan struct{}, 1),
		}
	}

	// For multiple targets, distribute threads more efficiently
	// Ensure we use all threads: perSite * siteConcurrent should be close to totalThreads
	siteConcurrent := int(math.Min(float64(totalThreads), float64(targetCount)))
	perSite := totalThreads / siteConcurrent
	if perSite < 1 {
		perSite = 1
	}

	// Adjust to ensure we use all threads when possible
	remainingThreads := totalThreads - (perSite * siteConcurrent)
	if remainingThreads > 0 && siteConcurrent < targetCount {
		// Distribute remaining threads to first sites
		perSite += remainingThreads / siteConcurrent
		if remainingThreads%siteConcurrent > 0 {
			perSite++
		}
	}

	return scanConfig{
		perSite:        perSite,
		siteConcurrent: siteConcurrent,
		sem:            make(chan struct{}, siteConcurrent),
	}
}

func createProgressManager(opts ScanOptions, targetCount int) *progress.ProgressManager {
	if opts.File != "" {
		return progress.NewProgressBar(targetCount, "🔎 Scanning...")
	}
	return progress.NewProgressBar(1, "🔎 Scanning...")
}

func createWriter(opts ScanOptions) file.WriterInterface {
	if opts.Output != "" {
		return file.GetWriter(opts.Output)
	}
	return nil
}

func closeWriter(writer file.WriterInterface) {
	if writer != nil {
		writer.Close()
	}
}

