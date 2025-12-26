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
	"os"
	"strconv"
	"testing"
)

func BenchmarkReadLines_Small(b *testing.B) {
	content := "line1\nline2\nline3\nline4\nline5\n"
	tmpfile, err := os.CreateTemp("", "bench_*.txt")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	if _, err := tmpfile.WriteString(content); err != nil {
		b.Fatal(err)
	}
	tmpfile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReadLines(tmpfile.Name())
	}
}

func BenchmarkReadLines_Medium(b *testing.B) {
	var content string
	for i := 0; i < 1000; i++ {
		content += "plugin" + strconv.Itoa(i) + "\n"
	}

	tmpfile, err := os.CreateTemp("", "bench_*.txt")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	if _, err := tmpfile.WriteString(content); err != nil {
		b.Fatal(err)
	}
	tmpfile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReadLines(tmpfile.Name())
	}
}

func BenchmarkReadLines_Large(b *testing.B) {
	var content string
	for i := 0; i < 10000; i++ {
		content += "plugin" + strconv.Itoa(i) + "\n"
	}

	tmpfile, err := os.CreateTemp("", "bench_*.txt")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	if _, err := tmpfile.WriteString(content); err != nil {
		b.Fatal(err)
	}
	tmpfile.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReadLines(tmpfile.Name())
	}
}

