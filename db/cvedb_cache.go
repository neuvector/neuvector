package db

import (
	"sync"

	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

// cvePrefixCache is a per-prefix lazy cache backed by the cvedb SQLite table.
// Each cache group holds all CVE entries sharing the same name prefix
// (e.g. "ubuntu" holds all "ubuntu:*" entries; "" holds bare CVE names).
// The cache is invalidated atomically after each CVEDB update so that all
// subsequent reads reload from the newly-committed SQLite data.
type cvePrefixCache struct {
	mu     sync.RWMutex
	groups map[string]map[string]*share.ScanVulnerability
}

var globalCVECache = &cvePrefixCache{
	groups: make(map[string]map[string]*share.ScanVulnerability),
}

// GlobalCVECache returns the singleton per-prefix CVE cache.
// It satisfies scan.CVELookup implicitly via the Get method.
func GlobalCVECache() *cvePrefixCache {
	return globalCVECache
}

// Get looks up a CVE entry by its full map key (e.g. "ubuntu:CVE-2021-1234").
// On a cache miss the relevant prefix group is loaded from SQLite and stored
// in the cache for subsequent callers.
func (c *cvePrefixCache) Get(name string) (*share.ScanVulnerability, bool) {
	prefix := prefixOf(name)

	// Fast path: group already loaded.
	c.mu.RLock()
	group, ok := c.groups[prefix]
	c.mu.RUnlock()
	if ok {
		v, found := group[name]
		return v, found
	}

	// Slow path: load from SQLite then store.  Re-check under write lock to
	// avoid a double-load race when two goroutines miss the same prefix at once.
	c.mu.Lock()
	defer c.mu.Unlock()
	if group, ok = c.groups[prefix]; ok {
		v, found := group[name]
		return v, found
	}

	loaded, err := LoadPrefixGroup(prefix)
	if err != nil {
		// Return a miss; the next caller will retry.
		log.WithError(err).Warn("failed to read cvedb from sqlitedb")
		return nil, false
	}
	c.groups[prefix] = loaded
	v, found := loaded[name]
	return v, found
}

// Invalidate clears all cached prefix groups.  Must be called AFTER a
// successful ReplaceCVEDB commit so that cache misses reload from the new data.
func (c *cvePrefixCache) Invalidate() {
	c.mu.Lock()
	c.groups = make(map[string]map[string]*share.ScanVulnerability)
	c.mu.Unlock()
}
