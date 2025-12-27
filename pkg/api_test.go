package wpprobe_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	wpprobe "github.com/Chocapikk/wpprobe/pkg"
)

func TestAPI_Scan(t *testing.T) {
	scanner, err := wpprobe.New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	cfg := wpprobe.Config{
		Target:    "http://localhost:9000",
		ScanMode:  "stealthy",
		Threads:   10,
		RateLimit: 5,
		Context:   context.Background(),
	}

	start := time.Now()
	result, err := scanner.Scan(cfg)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	if result.Target != cfg.Target {
		t.Errorf("Expected target %s, got %s", cfg.Target, result.Target)
	}

	fmt.Printf("\n=== Scan Results ===\n")
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Plugins found: %d\n", len(result.Plugins))
	fmt.Printf("Total vulnerabilities: %d\n", result.TotalVulnerabilities)
	fmt.Printf("Summary: Critical=%d, High=%d, Medium=%d, Low=%d\n",
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
	)

	if len(result.Plugins) > 0 {
		fmt.Printf("\n=== Detected Plugins ===\n")
		for i, plugin := range result.Plugins {
			if i >= 5 {
				fmt.Printf("... and %d more plugins\n", len(result.Plugins)-5)
				break
			}
			fmt.Printf("[%d] %s (v%s)\n", i+1, plugin.Name, plugin.Version)
			if len(plugin.Vulnerabilities.Critical) > 0 {
				fmt.Printf("    Critical: %d\n", len(plugin.Vulnerabilities.Critical))
			}
			if len(plugin.Vulnerabilities.High) > 0 {
				fmt.Printf("    High: %d\n", len(plugin.Vulnerabilities.High))
			}
			if len(plugin.Vulnerabilities.Medium) > 0 {
				fmt.Printf("    Medium: %d\n", len(plugin.Vulnerabilities.Medium))
			}
		}
	}

	if len(result.Plugins) == 0 {
		t.Log("Warning: No plugins detected. This might be expected if the target is not a WordPress site.")
	}
}

func TestAPI_ScanWithContext(t *testing.T) {
	scanner, err := wpprobe.New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := wpprobe.Config{
		Target:   "http://localhost:9000",
		ScanMode: "stealthy",
		Context:  ctx,
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	t.Logf("Scan completed with context: %d plugins found", len(result.Plugins))
}

func TestAPI_ScanWithProgress(t *testing.T) {
	scanner, err := wpprobe.New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	progressCalls := 0
	cfg := wpprobe.Config{
		Target:   "http://localhost:9000",
		ScanMode: "stealthy",
		ProgressCallback: func(message string, current, total int) {
			progressCalls++
			if progressCalls <= 3 {
				t.Logf("Progress: [%d/%d] %s", current, total, message)
			}
		},
	}

	result, err := scanner.Scan(cfg)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	t.Logf("Progress callback called %d times", progressCalls)
	t.Logf("Scan completed: %d plugins found", len(result.Plugins))
}

func TestAPI_UpdateDatabases(t *testing.T) {
	// Skip in CI to avoid rate limits and long execution times
	if testing.Short() {
		t.Skip("Skipping database update test in short mode")
	}

	// This test may take a while and requires network access
	err := wpprobe.UpdateDatabases()
	if err != nil {
		t.Logf("UpdateDatabases failed (this is OK if databases are already up to date or network issues): %v", err)
		// Don't fail the test, as this requires network and may hit rate limits
		return
	}

	t.Log("Databases updated successfully")
}

func TestAPI_Reload(t *testing.T) {
	scanner, err := wpprobe.New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Reload should work even if databases don't exist
	err = scanner.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	t.Log("Scanner reloaded successfully")
}
