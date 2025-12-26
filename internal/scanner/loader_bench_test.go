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
	"bytes"
	"strconv"
	"testing"
)

func BenchmarkLoadPluginEndpointsFromData_Small(b *testing.B) {
	data := []byte(`{"plugin1":["/endpoint1","/endpoint2"]}
{"plugin2":["/endpoint3","/endpoint4"]}
{"plugin3":["/endpoint5"]}
`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadPluginEndpointsFromData(data)
	}
}

func BenchmarkLoadPluginEndpointsFromData_Medium(b *testing.B) {
	var buf bytes.Buffer
	for i := 0; i < 100; i++ {
		buf.WriteString(`{"plugin`)
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(`":["/endpoint`)
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(`","/endpoint`)
		buf.WriteString(strconv.Itoa(i + 100))
		buf.WriteString(`"]}`)
		buf.WriteByte('\n')
	}
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadPluginEndpointsFromData(data)
	}
}

func BenchmarkLoadPluginEndpointsFromData_Large(b *testing.B) {
	var buf bytes.Buffer
	for i := 0; i < 1000; i++ {
		buf.WriteString(`{"plugin`)
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(`":["/endpoint`)
		buf.WriteString(strconv.Itoa(i))
		buf.WriteString(`","/endpoint`)
		buf.WriteString(strconv.Itoa(i + 1000))
		buf.WriteString(`","/endpoint`)
		buf.WriteString(strconv.Itoa(i + 2000))
		buf.WriteString(`"]}`)
		buf.WriteByte('\n')
	}
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = LoadPluginEndpointsFromData(data)
	}
}

