// Package state provides bounded rolling state stores for the detectors.
// All types are safe for concurrent use.
package state

import (
	"sync"
	"time"
)

const (
	// MaxDistinctValuesPerKey caps values in one rolling tracker entry.
	MaxDistinctValuesPerKey = 256
	// MaxDistinctValuesTotal caps all values retained by one Tracker.
	MaxDistinctValuesTotal = 4096
	// MaxTrackerKeys caps source/target keys in one Tracker.
	MaxTrackerKeys = 1024
	// MaxSamplesPerKey caps beacon timestamps for one source/destination pair.
	MaxSamplesPerKey = 64
	// MaxSamplesTotal caps beacon timestamps across all pairs.
	MaxSamplesTotal = 8192
)

// Tracker tracks a bounded set of distinct string values per source key
// within a rolling window. It caps source keys and retained values. New values
// are rejected when either value cap is full. Existing values stay.
type Tracker struct {
	mu         sync.Mutex
	entries    map[string]*trackerEntry
	window     time.Duration
	maxSources int
	values     int
}

type trackerEntry struct {
	vals            map[string]time.Time // value → last-seen timestamp
	lastSeen        time.Time
	threshold       int
	thresholdActive bool
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
	count, _, _ := t.addAt(key, val, time.Now(), 0)
	return count
}

// AddThreshold records a value and reports only the first threshold crossing
// in the current rolling episode. It returns a snapshot of the values on that
// crossing. A new episode starts when expiry lowers the count below threshold.
func (t *Tracker) AddThreshold(key, val string, threshold int) (int, bool, []string) {
	return t.addAt(key, val, time.Now(), threshold)
}

func (t *Tracker) addAt(key, val string, now time.Time, threshold int) (int, bool, []string) {
	cutoff := now.Add(-t.window)
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[key]
	if ok {
		t.expireValuesLocked(e, cutoff)
		if now.After(e.lastSeen) {
			e.lastSeen = now
		}
	} else {
		if t.maxSources <= 0 || t.values >= MaxDistinctValuesTotal {
			return 0, false, nil
		}
		if len(t.entries) >= t.maxSources {
			t.evictOldestLocked()
		}
		e = &trackerEntry{vals: make(map[string]time.Time), lastSeen: now}
		t.entries[key] = e
	}

	if _, exists := e.vals[val]; exists {
		e.vals[val] = now
	} else if len(e.vals) < MaxDistinctValuesPerKey && t.values < MaxDistinctValuesTotal {
		e.vals[val] = now
		t.values++
	}

	count := len(e.vals)
	if threshold <= 0 {
		return count, false, nil
	}
	e.threshold = threshold
	if count < threshold {
		e.thresholdActive = false
		return count, false, nil
	}
	if e.thresholdActive {
		return count, false, nil
	}
	e.thresholdActive = true
	values := make([]string, 0, count)
	for value := range e.vals {
		values = append(values, value)
	}
	return count, true, values
}

// Prune removes expired values and entries whose windows are fully empty.
func (t *Tracker) Prune() {
	cutoff := time.Now().Add(-t.window)
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, entry := range t.entries {
		t.expireValuesLocked(entry, cutoff)
		if len(entry.vals) == 0 {
			delete(t.entries, key)
		}
	}
}

func (t *Tracker) expireValuesLocked(entry *trackerEntry, cutoff time.Time) {
	for value, seenAt := range entry.vals {
		if seenAt.Before(cutoff) {
			delete(entry.vals, value)
			t.values--
		}
	}
	if entry.threshold > 0 && len(entry.vals) < entry.threshold {
		entry.thresholdActive = false
	}
}

// evictOldestLocked removes the entry with the oldest last-seen value.
func (t *Tracker) evictOldestLocked() {
	var oldest string
	var oldestSeen time.Time
	for key, entry := range t.entries {
		if oldest == "" || entry.lastSeen.Before(oldestSeen) {
			oldest = key
			oldestSeen = entry.lastSeen
		}
	}
	if oldest != "" {
		t.values -= len(t.entries[oldest].vals)
		delete(t.entries, oldest)
	}
}
