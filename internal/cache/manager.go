// Package cache is a TTL cache shared by the collectors.
package cache

import (
	"sync"
	"time"
)

// Entry represents a cached value with expiration.
type Entry struct {
	Value     any
	ExpiresAt time.Time
}

// IsExpired checks if the cache entry has expired.
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Manager provides centralized caching for all collectors.
type Manager struct {
	mu      sync.RWMutex
	entries map[string]*Entry
}

// NewManager creates a new cache manager.
func NewManager() *Manager {
	return &Manager{
		entries: make(map[string]*Entry),
	}
}

// Get retrieves a value from cache if not expired.
func (m *Manager) Get(key string) (any, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.entries[key]
	if !exists || entry.IsExpired() {
		return nil, false
	}

	return entry.Value, true
}

// Set stores a value in cache with TTL.
func (m *Manager) Set(key string, value any, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries[key] = &Entry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// CleanExpired removes expired entries.
func (m *Manager) CleanExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, entry := range m.entries {
		if now.After(entry.ExpiresAt) {
			delete(m.entries, key)
		}
	}
}

// StartCleanup starts periodic cleanup of expired entries.
func (m *Manager) StartCleanup(interval time.Duration) chan struct{} {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.CleanExpired()
			case <-stop:
				return
			}
		}
	}()
	return stop
}

// Global cache instance for all collectors.
var globalCache = NewManager()

// Get retrieves from global cache.
func Get(key string) (any, bool) {
	return globalCache.Get(key)
}

// Set stores in global cache.
func Set(key string, value any, ttl time.Duration) {
	globalCache.Set(key, value, ttl)
}

// StartGlobalCleanup starts cleanup for global cache.
func StartGlobalCleanup(interval time.Duration) chan struct{} {
	return globalCache.StartCleanup(interval)
}
