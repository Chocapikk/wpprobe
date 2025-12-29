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

package file

import (
	"sync"
)

// MemoryWriter stores scan results in memory for retrieval via API.
type MemoryWriter struct {
	mu      sync.Mutex
	results []PluginEntry
}

// NewMemoryWriter creates a new memory writer.
func NewMemoryWriter() *MemoryWriter {
	return &MemoryWriter{
		results: make([]PluginEntry, 0, 32), // Pre-allocate for typical scan size
	}
}

// WriteResults stores results in memory.
func (m *MemoryWriter) WriteResults(url string, results []PluginEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, results...)
}

// GetResults returns all stored results.
// Note: Returns the internal slice directly for performance.
// Caller should not modify the returned slice.
func (m *MemoryWriter) GetResults() []PluginEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.results
}

// Close clears the results to free memory.
func (m *MemoryWriter) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = nil
}

