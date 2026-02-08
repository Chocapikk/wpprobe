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
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/Chocapikk/wpprobe/internal/http"
)

func fetchEndpointsFromPath(ctx context.Context, target, path string, httpClient *http.HTTPClientManager) []string {
	response, err := httpClient.GetWithContext(ctx, target+path)
	if err != nil {
		return []string{}
	}

	var jsonData map[string]interface{}
	if err := json.NewDecoder(strings.NewReader(response)).Decode(&jsonData); err != nil {
		return []string{}
	}

	routes, ok := jsonData["routes"].(map[string]interface{})
	if !ok {
		return []string{}
	}

	endpoints := make([]string, 0, len(routes))
	for route := range routes {
		endpoints = append(endpoints, route)
	}

	return endpoints
}

func FetchEndpoints(ctx context.Context, target string, cfg http.Config) []string {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-ctx.Done():
		return []string{}
	default:
	}

	httpClient := cfg.NewClient(5 * time.Second)

	endpointsChan := make(chan []string, 2)
	var wg sync.WaitGroup

	paths := []string{"/?rest_route=/", "/wp-json"}

	for _, path := range paths {
		wg.Add(1)
		go fetchEndpointsWorker(ctx, target, path, httpClient, endpointsChan, &wg)
	}

	go closeEndpointsChannel(&wg, endpointsChan)

	uniqueEndpoints := make(map[string]struct{})
	for epList := range endpointsChan {
		for _, ep := range epList {
			uniqueEndpoints[ep] = struct{}{}
		}
	}

	finalEndpoints := make([]string, 0, len(uniqueEndpoints))
	for ep := range uniqueEndpoints {
		finalEndpoints = append(finalEndpoints, ep)
	}

	return finalEndpoints
}

func fetchEndpointsWorker(
	ctx context.Context,
	target string,
	path string,
	httpClient *http.HTTPClientManager,
	endpointsChan chan []string,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	endpoints := fetchEndpointsFromPath(ctx, target, path, httpClient)
	endpointsChan <- endpoints
}

func closeEndpointsChannel(wg *sync.WaitGroup, endpointsChan chan []string) {
	wg.Wait()
	close(endpointsChan)
}
