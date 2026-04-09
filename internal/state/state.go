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
	vals map[string]time.Time // value → last-seen timestamp
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
// that key within the sliding window. Values older than window are expired on
// each call so the count always reflects only the recent window.
func (t *Tracker) Add(key, val string) int {
	now := time.Now()
	cutoff := now.Add(-t.window)
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[key]
	if !ok {
		if len(t.entries) >= t.maxSources {
			t.evictOldestLocked(now)
		}
		e = &trackerEntry{vals: make(map[string]time.Time)}
		t.entries[key] = e
	}
	e.vals[val] = now

	// Trim values that have fallen outside the sliding window.
	for v, ts := range e.vals {
		if ts.Before(cutoff) {
			delete(e.vals, v)
		}
	}
	return len(e.vals)
}

// Prune removes entries whose sliding windows are fully empty.
func (t *Tracker) Prune() {
	now := time.Now()
	cutoff := now.Add(-t.window)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.entries {
		for v, ts := range e.vals {
			if ts.Before(cutoff) {
				delete(e.vals, v)
			}
		}
		if len(e.vals) == 0 {
			delete(t.entries, k)
		}
	}
}

// evictOldestLocked removes the entry whose most-recently-seen value is oldest.
func (t *Tracker) evictOldestLocked(now time.Time) {
	var oldest string
	var oldestLatest time.Time
	for k, e := range t.entries {
		var latest time.Time
		for _, ts := range e.vals {
			if ts.After(latest) {
				latest = ts
			}
		}
		if oldest == "" || latest.Before(oldestLatest) {
			oldest = k
			oldestLatest = latest
		}
	}
	if oldest != "" {
		delete(t.entries, oldest)
	}
}
