// Package state provides bounded rolling state stores for the detectors.
// All types are safe for concurrent use.
package state

import (
	"sync"
	"time"
)

// Tracker tracks a bounded set of distinct string values per source key
// within a rolling time window. When a key's window expires its count resets.
// At most maxSources keys are held; the oldest-expiring key is evicted when
// the limit is reached.
type Tracker struct {
	mu         sync.Mutex
	entries    map[string]*trackerEntry
	window     time.Duration
	maxSources int
}

type trackerEntry struct {
	vals    map[string]struct{}
	expires time.Time
}

// NewTracker creates a Tracker with the given window and source key limit.
func NewTracker(window time.Duration, maxSources int) *Tracker {
	return &Tracker{
		entries:    make(map[string]*trackerEntry),
		window:     window,
		maxSources: maxSources,
	}
}

// Add records val under key and returns the current distinct value count for
// that key. If the key's window has expired the count resets before adding.
func (t *Tracker) Add(key, val string) int {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[key]
	if !ok || now.After(e.expires) {
		if !ok && len(t.entries) >= t.maxSources {
			t.evictOldestLocked()
		}
		e = &trackerEntry{
			vals:    make(map[string]struct{}),
			expires: now.Add(t.window),
		}
		t.entries[key] = e
	}
	e.vals[val] = struct{}{}
	return len(e.vals)
}

// Prune removes all entries whose window has expired.
func (t *Tracker) Prune() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.entries {
		if now.After(e.expires) {
			delete(t.entries, k)
		}
	}
}

func (t *Tracker) evictOldestLocked() {
	var oldest string
	var oldestExp time.Time
	for k, e := range t.entries {
		if oldest == "" || e.expires.Before(oldestExp) {
			oldest = k
			oldestExp = e.expires
		}
	}
	if oldest != "" {
		delete(t.entries, oldest)
	}
}
