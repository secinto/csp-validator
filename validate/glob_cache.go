package validate

import (
	"sync"

	"github.com/gobwas/glob"
)

// GlobCache provides thread-safe caching of compiled glob patterns to improve
// performance when parsing CSP policies with repeated glob patterns.
//
// The cache uses a read-write mutex to allow concurrent reads while ensuring
// exclusive access during writes. Both successful compilations and errors are
// cached to avoid recompiling invalid patterns.
//
// Example usage:
//
//	cache := NewGlobCache()
//	g, err := cache.CompileWithDelimiter("*.example.com", '/')
//	if err != nil {
//	    // Handle error
//	}
//	// Subsequent calls with the same pattern will return cached results
type GlobCache struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// cacheEntry stores a compiled glob pattern and any compilation error.
// Both successful and failed compilations are cached to avoid redundant work.
type cacheEntry struct {
	pattern glob.Glob
	err     error
}

// NewGlobCache creates a new empty glob pattern cache.
// The cache is safe for concurrent use by multiple goroutines.
func NewGlobCache() *GlobCache {
	return &GlobCache{
		cache: make(map[string]cacheEntry),
	}
}

// Compile compiles a glob pattern using the cache.
// If the pattern has been compiled before, returns the cached result.
// This is equivalent to calling CompileWithDelimiter with a zero delimiter.
func (c *GlobCache) Compile(pattern string) (glob.Glob, error) {
	return c.CompileWithDelimiter(pattern, 0)
}

// CompileWithDelimiter compiles a glob pattern with a delimiter using the cache.
// The delimiter parameter is used as part of the cache key, allowing the same
// pattern string to be compiled with different delimiters.
//
// If the pattern+delimiter combination has been compiled before (successfully or
// with an error), the cached result is returned immediately. Otherwise, the pattern
// is compiled and the result is cached for future use.
//
// The function uses double-checked locking to minimize contention:
//  1. Fast path: Check cache with read lock
//  2. Slow path: Acquire write lock, double-check, then compile and cache
func (c *GlobCache) CompileWithDelimiter(pattern string, delimiter rune) (glob.Glob, error) {
	// Create cache key that includes delimiter
	cacheKey := pattern
	if delimiter != 0 {
		cacheKey = pattern + string(delimiter)
	}

	// Try to read from cache first (read lock)
	c.mu.RLock()
	if entry, found := c.cache[cacheKey]; found {
		c.mu.RUnlock()
		return entry.pattern, entry.err
	}
	c.mu.RUnlock()

	// Not in cache, compile with write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine might have added it)
	if entry, found := c.cache[cacheKey]; found {
		return entry.pattern, entry.err
	}

	// Compile the pattern
	var g glob.Glob
	var err error
	if delimiter != 0 {
		g, err = glob.Compile(pattern, delimiter)
	} else {
		g, err = glob.Compile(pattern)
	}

	// Store in cache (even if there was an error, to avoid recompiling bad patterns)
	c.cache[cacheKey] = cacheEntry{
		pattern: g,
		err:     err,
	}

	return g, err
}

// Size returns the number of cached pattern entries.
// This includes both successful compilations and cached errors.
func (c *GlobCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Clear removes all cached patterns and frees associated memory.
// This is useful for resetting the cache between test runs or
// when memory usage needs to be reduced.
func (c *GlobCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]cacheEntry)
}
