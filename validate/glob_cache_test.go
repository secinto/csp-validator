package validate

import (
	"sync"
	"testing"
)

func TestNewGlobCache(t *testing.T) {
	cache := NewGlobCache()
	if cache == nil {
		t.Fatal("NewGlobCache() returned nil")
	}
	if cache.Size() != 0 {
		t.Errorf("NewGlobCache().Size() = %d; want 0", cache.Size())
	}
}

func TestGlobCache_Compile(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		wantErr     bool
		shouldMatch string
	}{
		{
			name:        "simple wildcard",
			pattern:     "*.example.com",
			wantErr:     false,
			shouldMatch: "www.example.com",
		},
		{
			name:        "exact match",
			pattern:     "example.com",
			wantErr:     false,
			shouldMatch: "example.com",
		},
		{
			name:        "multiple wildcards",
			pattern:     "*://*.example.com",
			wantErr:     false,
			shouldMatch: "https://www.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewGlobCache()

			// First call - should compile
			g1, err1 := cache.Compile(tt.pattern)
			if (err1 != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err1, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if !g1.Match(tt.shouldMatch) {
					t.Errorf("Compile(%q).Match(%q) = false; want true", tt.pattern, tt.shouldMatch)
				}
			}

			// Second call - should return cached
			g2, err2 := cache.Compile(tt.pattern)
			if (err2 != nil) != tt.wantErr {
				t.Errorf("Compile() (cached) error = %v, wantErr %v", err2, tt.wantErr)
				return
			}

			// Verify caching worked
			if cache.Size() != 1 {
				t.Errorf("cache.Size() = %d; want 1", cache.Size())
			}

			if !tt.wantErr && !g2.Match(tt.shouldMatch) {
				t.Errorf("Compile(%q) (cached).Match(%q) = false; want true", tt.pattern, tt.shouldMatch)
			}
		})
	}
}

func TestGlobCache_CompileWithDelimiter(t *testing.T) {
	cache := NewGlobCache()

	pattern := "a/b/c"

	// Compile with delimiter
	g1, err := cache.CompileWithDelimiter(pattern, '/')
	if err != nil {
		t.Fatalf("CompileWithDelimiter() error = %v", err)
	}

	if !g1.Match("a/b/c") {
		t.Error("CompileWithDelimiter() pattern doesn't match expected string")
	}

	// Compile same pattern without delimiter - should be separate cache entry
	g2, err := cache.CompileWithDelimiter(pattern, 0)
	if err != nil {
		t.Fatalf("CompileWithDelimiter() (no delim) error = %v", err)
	}

	// Should have 2 cache entries
	if cache.Size() != 2 {
		t.Errorf("cache.Size() = %d; want 2 (different delimiters)", cache.Size())
	}

	// Compile again with delimiter - should use cache
	g3, err := cache.CompileWithDelimiter(pattern, '/')
	if err != nil {
		t.Fatalf("CompileWithDelimiter() (cached) error = %v", err)
	}

	if !g3.Match("a/b/c") {
		t.Error("CompileWithDelimiter() (cached) pattern doesn't match expected string")
	}

	// Should still have 2 cache entries
	if cache.Size() != 2 {
		t.Errorf("cache.Size() = %d; want 2 (cached access shouldn't add entry)", cache.Size())
	}
}

func TestGlobCache_CachesErrors(t *testing.T) {
	cache := NewGlobCache()

	// Invalid pattern (unclosed bracket)
	invalidPattern := "[invalid"

	// First call - should fail to compile
	_, err1 := cache.Compile(invalidPattern)
	if err1 == nil {
		t.Error("Compile() with invalid pattern should return error")
	}

	// Should be cached (even errors are cached)
	if cache.Size() != 1 {
		t.Errorf("cache.Size() = %d; want 1 (errors should be cached)", cache.Size())
	}

	// Second call - should return cached error
	_, err2 := cache.Compile(invalidPattern)
	if err2 == nil {
		t.Error("Compile() (cached) with invalid pattern should return error")
	}

	// Size should still be 1
	if cache.Size() != 1 {
		t.Errorf("cache.Size() = %d; want 1", cache.Size())
	}
}

func TestGlobCache_Clear(t *testing.T) {
	cache := NewGlobCache()

	// Add some patterns
	patterns := []string{"*.com", "*.org", "*.net"}
	for _, p := range patterns {
		_, err := cache.Compile(p)
		if err != nil {
			t.Fatalf("Compile(%q) error = %v", p, err)
		}
	}

	if cache.Size() != len(patterns) {
		t.Errorf("cache.Size() = %d; want %d", cache.Size(), len(patterns))
	}

	// Clear the cache
	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("cache.Size() after Clear() = %d; want 0", cache.Size())
	}

	// Should be able to add patterns again
	_, err := cache.Compile("*.com")
	if err != nil {
		t.Fatalf("Compile() after Clear() error = %v", err)
	}

	if cache.Size() != 1 {
		t.Errorf("cache.Size() after adding new pattern = %d; want 1", cache.Size())
	}
}

func TestGlobCache_Concurrent(t *testing.T) {
	cache := NewGlobCache()
	patterns := []string{
		"*.example.com",
		"*.test.org",
		"*.demo.net",
		"foo.bar.com",
		"https://*.secure.com",
	}

	// Number of goroutines
	numGoroutines := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch multiple goroutines that compile patterns concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine compiles all patterns multiple times
			for j := 0; j < 10; j++ {
				for _, pattern := range patterns {
					g, err := cache.Compile(pattern)
					if err != nil {
						t.Errorf("goroutine %d: Compile(%q) error = %v", id, pattern, err)
						return
					}

					// Verify the pattern works
					if pattern == "*.example.com" && !g.Match("www.example.com") {
						t.Errorf("goroutine %d: pattern %q doesn't match expected", id, pattern)
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Should only have one entry per unique pattern
	if cache.Size() != len(patterns) {
		t.Errorf("cache.Size() after concurrent access = %d; want %d", cache.Size(), len(patterns))
	}
}

func TestGlobCache_ConcurrentWithDelimiter(t *testing.T) {
	cache := NewGlobCache()
	pattern := "a/b/c"

	numGoroutines := 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // Each goroutine will be called twice (with and without delimiter)

	// Test concurrent access with delimiter
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			g, err := cache.CompileWithDelimiter(pattern, '/')
			if err != nil {
				t.Errorf("CompileWithDelimiter() error = %v", err)
				return
			}
			if !g.Match("a/b/c") {
				t.Error("Pattern doesn't match")
			}
		}()

		go func() {
			defer wg.Done()
			g, err := cache.CompileWithDelimiter(pattern, 0)
			if err != nil {
				t.Errorf("CompileWithDelimiter() (no delim) error = %v", err)
				return
			}
			_ = g // Just verify no error
		}()
	}

	wg.Wait()

	// Should have exactly 2 entries (one for each delimiter variant)
	if cache.Size() != 2 {
		t.Errorf("cache.Size() after concurrent access = %d; want 2", cache.Size())
	}
}

func BenchmarkGlobCache_Compile(b *testing.B) {
	cache := NewGlobCache()
	pattern := "*.example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Compile(pattern)
	}
}

func BenchmarkGlobCache_CompileMultiplePatterns(b *testing.B) {
	cache := NewGlobCache()
	patterns := []string{
		"*.example.com",
		"*.test.org",
		"*.demo.net",
		"https://*.secure.com",
		"http://*.insecure.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pattern := range patterns {
			_, _ = cache.Compile(pattern)
		}
	}
}

func BenchmarkGlobCache_ConcurrentAccess(b *testing.B) {
	cache := NewGlobCache()
	pattern := "*.example.com"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = cache.Compile(pattern)
		}
	})
}
