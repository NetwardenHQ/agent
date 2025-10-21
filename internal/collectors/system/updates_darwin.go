//go:build darwin

package system

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GetAvailableUpdates returns the number of available system updates on macOS.
// It safely checks Software Update information without executing commands.
func (c *Collector) GetAvailableUpdates(ctx context.Context) (int, error) {
	// Try multiple methods to get update count

	// Method 1: Check Software Update preference files
	if count, err := checkSoftwareUpdatePrefs(); err == nil && count > 0 {
		return count, nil
	}

	// Method 2: Check Software Update cache
	if count, err := checkSoftwareUpdateCache(); err == nil && count > 0 {
		return count, nil
	}

	// Method 3: Check App Store update receipts
	if count, err := checkAppStoreUpdates(); err == nil && count > 0 {
		return count, nil
	}

	// No updates found or couldn't read update info
	return 0, nil
}

// checkSoftwareUpdatePrefs checks Software Update preference files.
func checkSoftwareUpdatePrefs() (int, error) {
	// macOS stores software update preferences in plist files
	prefFiles := []string{
		"/Library/Preferences/com.apple.SoftwareUpdate.plist",
		filepath.Join(os.Getenv("HOME"), "Library/Preferences/com.apple.SoftwareUpdate.plist"),
	}

	for _, prefFile := range prefFiles {
		if data, err := os.ReadFile(prefFile); err == nil {
			// Look for RecommendedUpdates key in plist
			// This is a simple text search since we're avoiding command execution
			if strings.Contains(string(data), "RecommendedUpdates") {
				// Count array entries between RecommendedUpdates tags
				content := string(data)
				start := strings.Index(content, "RecommendedUpdates")
				if start >= 0 {
					// Look for array elements after this key
					section := content[start:]
					// Count <dict> entries which represent updates
					count := strings.Count(section, "<dict>")
					// Subtract nested dicts (rough estimate)
					count = count / 2
					if count > 0 {
						return count, nil
					}
				}
			}
		}
	}

	return 0, os.ErrNotExist
}

// checkSoftwareUpdateCache checks the Software Update cache directory.
func checkSoftwareUpdateCache() (int, error) {
	// macOS caches update information in specific directories
	cacheDirs := []string{
		"/Library/Updates",
		"/System/Library/CoreServices/Software Update.app/Contents/Resources",
	}

	for _, cacheDir := range cacheDirs {
		if _, err := os.Stat(cacheDir); err == nil {
			// Check for index.plist which lists available updates
			indexFile := filepath.Join(cacheDir, "index.plist")
			if data, err := os.ReadFile(indexFile); err == nil {
				// Count ProductKey entries which indicate updates
				count := strings.Count(string(data), "ProductKey")
				if count > 0 {
					return count, nil
				}
			}

			// Check for downloaded update packages
			updatePkgs := 0
			entries, err := os.ReadDir(cacheDir)
			if err == nil {
				for _, entry := range entries {
					// Count .pkg files or update directories
					if strings.HasSuffix(entry.Name(), ".pkg") ||
						strings.HasSuffix(entry.Name(), ".dist") ||
						strings.Contains(entry.Name(), "Update") {
						updatePkgs++
					}
				}
			}
			if updatePkgs > 0 {
				return updatePkgs, nil
			}
		}
	}

	return 0, os.ErrNotExist
}

// checkAppStoreUpdates checks for App Store updates.
func checkAppStoreUpdates() (int, error) {
	// Check App Store update information
	home := os.Getenv("HOME")
	if home == "" {
		return 0, os.ErrNotExist
	}

	// App Store stores update info in its cache
	appStoreCacheFile := filepath.Join(home, "Library", "Caches", "com.apple.appstore", "updateAvailable")
	if data, err := os.ReadFile(appStoreCacheFile); err == nil {
		// Simple format: number of available updates
		countStr := strings.TrimSpace(string(data))
		if count, err := strconv.Atoi(countStr); err == nil {
			return count, nil
		}
	}

	// Check storeagent database for pending updates
	storeDbPath := filepath.Join(home, "Library", "Application Support", "App Store", "storeagent.db")
	if _, err := os.Stat(storeDbPath); err == nil {
		// Database exists, but we can't parse SQLite without libraries
		// This at least confirms App Store is configured
		return 0, nil
	}

	return 0, os.ErrNotExist
}

// GetSecurityUpdates returns the number of available security updates on macOS.
// macOS doesn't distinguish between regular and security updates in available data.
func (c *Collector) GetSecurityUpdates(ctx context.Context) (int, error) {
	// macOS doesn't provide separate security update counts
	// Return 0 as security updates are included in general updates
	return 0, nil
}
