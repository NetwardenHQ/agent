//go:build windows

package system

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Cache update count for 6 hours to avoid repeated checks
// Windows Update checking is slow (~5-10 seconds) but provides accurate data
// Background goroutine checks for updates every 6 hours and populates this cache
// Caching eliminates the overhead for 60-second collection cycles
var (
	cachedUpdateCount      int
	cachedSecurityCount    int
	updateCacheExpiry      time.Time
	updateCacheMutex       sync.Mutex
	updateCacheInitialized bool
)

// updateResult represents a single Windows Update
type updateResult struct {
	Title          string `json:"Title"`
	IsDownloaded   bool   `json:"IsDownloaded"`
	IsInstalled    bool   `json:"IsInstalled"`
	IsMandatory    bool   `json:"IsMandatory"`
	MsrcSeverity   string `json:"MsrcSeverity"`
	SecurityRating int    `json:"SecurityRating"`
}

// getAvailableUpdates returns the number of available system updates using PowerShell CIM method.
// This replaces COM-based methods which:
// - Crash on ARM64 Windows due to x86/x64 emulation issues with COM DLLs
// - Reference: https://github.com/microsoft/Detours/issues/292
//
// PowerShell CIM method is:
// - Official Microsoft API for update checking (non-COM)
// - Accurate and reliable across all architectures
// - Slower (~5-10 seconds) but cached for 6 hours
// - Works on ARM64 Windows without crashes
func (c *Collector) GetAvailableUpdates(ctx context.Context) (int, error) {
	updateCacheMutex.Lock()
	defer updateCacheMutex.Unlock()

	// Return cached value if still fresh (6 hours)
	if updateCacheInitialized && time.Now().Before(updateCacheExpiry) {
		c.logger.Debug("Returning cached Windows Update count",
			"total_updates", cachedUpdateCount,
			"security_updates", cachedSecurityCount,
			"cache_expires_in", time.Until(updateCacheExpiry).Round(time.Minute).String())
		return cachedUpdateCount, nil
	}

	c.logger.Debug("Querying Windows Update via PowerShell CIM (cache expired or first run)")

	// Use PowerShell Invoke-CimMethod to scan for updates (non-COM approach)
	// This avoids COM API crashes on ARM64 with x86/x64 emulation
	type searchResult struct {
		updateCount   int
		securityCount int
		err           error
	}
	resultChan := make(chan searchResult, 1)

	// Run PowerShell in goroutine to enable timeout
	go func() {
		// Timeout based on architecture - ARM64 emulation is slower
		timeout := 30 * time.Second
		if runtime.GOARCH == "arm64" {
			timeout = 60 * time.Second // ARM64 needs more time for emulation overhead
		}

		cmdCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		// PowerShell script to scan for updates using CIM method (non-COM)
		// This is the official Microsoft-recommended approach that works on ARM64
		psScript := `
		try {
			$result = Invoke-CimMethod -Namespace root/microsoft/windows/windowsupdate -ClassName MSFT_WUOperations -MethodName ScanForUpdates -Arguments @{SearchCriteria="IsInstalled=0"}
			$updates = $result.Updates
			$total = $updates.Count
			$security = ($updates | Where-Object { $_.MsrcSeverity -ne $null }).Count
			Write-Output "$total,$security"
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
		`

		cmd := exec.CommandContext(cmdCtx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
		output, err := cmd.Output()
		if err != nil {
			resultChan <- searchResult{0, 0, fmt.Errorf("PowerShell CIM scan failed: %w", err)}
			return
		}

		// Parse output: "total,security"
		parts := strings.Split(strings.TrimSpace(string(output)), ",")
		if len(parts) != 2 {
			resultChan <- searchResult{0, 0, fmt.Errorf("invalid PowerShell output format: %s", output)}
			return
		}

		var totalCount, securityCount int
		fmt.Sscanf(parts[0], "%d", &totalCount)
		fmt.Sscanf(parts[1], "%d", &securityCount)

		resultChan <- searchResult{totalCount, securityCount, nil}
	}()

	// Wait for result with architecture-specific timeout
	timeout := 35 * time.Second
	if runtime.GOARCH == "arm64" {
		timeout = 65 * time.Second
	}

	select {
	case res := <-resultChan:
		if res.err != nil {
			c.logger.Warn("Windows Update scan failed", "error", res.err)
			if updateCacheInitialized {
				c.logger.Info("Returning cached update count due to scan error",
					"cached_count", cachedUpdateCount)
				return cachedUpdateCount, nil
			}
			return 0, res.err
		}

		// Cache the results for 6 hours
		cachedUpdateCount = res.updateCount
		cachedSecurityCount = res.securityCount
		updateCacheExpiry = time.Now().Add(6 * time.Hour)
		updateCacheInitialized = true

		c.logger.Info("Windows Update check completed via PowerShell CIM",
			"total_updates", cachedUpdateCount,
			"security_updates", cachedSecurityCount,
			"cache_valid_until", updateCacheExpiry.Format(time.RFC3339))

		return cachedUpdateCount, nil

	case <-time.After(timeout):
		// Timeout
		c.logger.Warn("Windows Update scan timed out",
			"timeout_seconds", timeout.Seconds(),
			"arch", runtime.GOARCH)
		if updateCacheInitialized {
			c.logger.Info("Returning cached update count due to timeout",
				"cached_count", cachedUpdateCount)
			return cachedUpdateCount, nil
		}
		return 0, fmt.Errorf("windows update scan timed out after %v", timeout)

	case <-ctx.Done():
		// Context cancelled
		if updateCacheInitialized {
			return cachedUpdateCount, nil
		}
		return 0, ctx.Err()
	}
}

// getSecurityUpdates returns the number of available security updates on Windows.
// Security updates are those with MsrcSeverity field set (Critical, Important, Moderate, Low).
// This data is cached along with total update count for 6 hours.
func (c *Collector) GetSecurityUpdates(ctx context.Context) (int, error) {
	updateCacheMutex.Lock()
	defer updateCacheMutex.Unlock()

	// If cache is valid, return cached security count
	if updateCacheInitialized && time.Now().Before(updateCacheExpiry) {
		c.logger.Debug("Returning cached security update count",
			"security_updates", cachedSecurityCount,
			"cache_expires_in", time.Until(updateCacheExpiry).Round(time.Minute).String())
		return cachedSecurityCount, nil
	}

	// Cache is expired or not initialized
	// Unlock mutex before calling GetAvailableUpdates to avoid deadlock
	updateCacheMutex.Unlock()
	_, err := c.GetAvailableUpdates(ctx)
	updateCacheMutex.Lock()

	// After getAvailableUpdates completes, security count should be cached
	if err != nil {
		c.logger.Warn("Failed to get security update count", "error", err)
		return 0, err
	}

	return cachedSecurityCount, nil
}
