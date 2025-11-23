package validate

import (
	"sync"

	"github.com/gobwas/glob"
)

// GlobCache provides thread-safe caching of compiled glob patterns
type GlobCache struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// cacheEntry stores a compiled glob pattern and any compilation error
type cacheEntry struct {
	pattern glob.Glob
	err     error
}

// NewGlobCache creates a new glob pattern cache
func NewGlobCache() *GlobCache {
	return &GlobCache{
		cache: make(map[string]cacheEntry),
	}
}

// Compile compiles a glob pattern using the cache
// If the pattern has been compiled before, returns the cached result
func (c *GlobCache) Compile(pattern string) (glob.Glob, error) {
	return c.CompileWithDelimiter(pattern, 0)
}

// CompileWithDelimiter compiles a glob pattern with a delimiter using the cache
// The delimiter parameter is used as part of the cache key
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

// Size returns the number of cached patterns
func (c *GlobCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Clear removes all cached patterns
func (c *GlobCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]cacheEntry)
}
