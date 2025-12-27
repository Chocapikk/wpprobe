# WPProbe Public API

This package provides a public API for scanning WordPress sites for plugins and vulnerabilities. It's designed to be integrated into other security tools and scanners.

## Quick Start

```go
import "github.com/Chocapikk/wpprobe/pkg"

// Create scanner
scanner, err := pkg.New()
if err != nil {
    log.Fatal(err)
}

// Scan a WordPress site
result, err := scanner.Scan(pkg.Config{
    Target:   "https://example.com",
    ScanMode: "stealthy", // or "bruteforce" or "hybrid"
    Threads:  10,
    RateLimit: 5,
    Context:  context.Background(),
})

// Process results
for _, plugin := range result.Plugins {
    fmt.Printf("Plugin: %s (v%s)\n", plugin.Name, plugin.Version)
    fmt.Printf("  Critical: %d\n", len(plugin.Vulnerabilities.Critical))
    fmt.Printf("  High: %d\n", len(plugin.Vulnerabilities.High))
}
```

## Configuration

- `Target`: WordPress site URL to scan
- `ScanMode`: "stealthy" (default), "bruteforce", or "hybrid"
- `Threads`: Number of concurrent threads (default: 10)
- `RateLimit`: Requests per second (0 = unlimited, default: 0)
- `Headers`: Custom HTTP headers
- `Proxy`: Proxy URL
- `PluginList`: Path to plugin list file (for bruteforce/hybrid)
- `NoCheckVersion`: Skip version checking
- `Context`: Context for cancellation
- `ProgressCallback`: Optional progress callback

## Integration Examples

See `example_test.go` for a complete example of how to use the WPProbe API in your own tools.

## Testing

Run the test script:
```bash
go run test_api.go http://localhost:9000
```

