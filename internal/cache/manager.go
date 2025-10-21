// Package cache provides a centralized cache manager for all collectors.
package cache

import (
	"sync"
	"time"
)

// Entry represents a cached value with expiration.
type Entry struct {
	Value     interface{}
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
func (m *Manager) Get(key string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.entries[key]
	if !exists || entry.IsExpired() {
		return nil, false
	}

	return entry.Value, true
}

// Set stores a value in cache with TTL.
func (m *Manager) Set(key string, value interface{}, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries[key] = &Entry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// Delete removes a value from cache.
func (m *Manager) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.entries, key)
}

// Clear removes all entries from cache.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries = make(map[string]*Entry)
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

// Size returns the number of entries in cache.
func (m *Manager) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

// Global cache instance for all collectors.
var globalCache = NewManager()

// Get retrieves from global cache.
func Get(key string) (interface{}, bool) {
	return globalCache.Get(key)
}

// Set stores in global cache.
func Set(key string, value interface{}, ttl time.Duration) {
	globalCache.Set(key, value, ttl)
}

// Delete removes from global cache.
func Delete(key string) {
	globalCache.Delete(key)
}

// Clear clears global cache.
func Clear() {
	globalCache.Clear()
}

// StartGlobalCleanup starts cleanup for global cache.
func StartGlobalCleanup(interval time.Duration) chan struct{} {
	return globalCache.StartCleanup(interval)
}
