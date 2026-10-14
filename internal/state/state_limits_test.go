package state

import (
	"fmt"
	"testing"
	"time"
)

func TestTrackerRejectsNewValuesAtPerKeyAndTotalLimits(t *testing.T) {
	tracker := NewTracker(time.Minute, 32)
	base := time.Unix(1_800_000_000, 0)

	for i := range MaxDistinctValuesPerKey {
		count, _, _ := tracker.addAt("source-0", fmt.Sprintf("value-%d", i), base, 0)
		if count != i+1 {
			t.Fatalf("per-key value %d: got count %d", i, count)
		}
	}
	count, _, _ := tracker.addAt("source-0", "per-key-overflow", base, 0)
	if count != MaxDistinctValuesPerKey || tracker.values != MaxDistinctValuesPerKey {
		t.Fatalf("per-key overflow: count=%d retained=%d", count, tracker.values)
	}
	if _, exists := tracker.entries["source-0"].vals["per-key-overflow"]; exists {
		t.Fatal("tracker retained a value beyond its per-key limit")
	}

	for key := 1; key < MaxDistinctValuesTotal/MaxDistinctValuesPerKey; key++ {
		for value := range MaxDistinctValuesPerKey {
			tracker.addAt(fmt.Sprintf("source-%d", key), fmt.Sprintf("value-%d", value), base, 0)
		}
	}
	if tracker.values != MaxDistinctValuesTotal {
		t.Fatalf("total retained values: got %d, want %d", tracker.values, MaxDistinctValuesTotal)
	}
	count, _, _ = tracker.addAt("overflow-source", "value", base, 0)
	if count != 0 || tracker.values != MaxDistinctValuesTotal {
		t.Fatalf("total overflow: count=%d retained=%d", count, tracker.values)
	}
	if _, exists := tracker.entries["overflow-source"]; exists {
		t.Fatal("tracker created a source entry after the total limit")
	}

	count, _, _ = tracker.addAt("source-0", "fresh-value", base.Add(2*time.Minute), 0)
	if count != 1 || tracker.values != MaxDistinctValuesTotal-(MaxDistinctValuesPerKey-1) {
		t.Fatalf("expired values were not reclaimed: count=%d retained=%d", count, tracker.values)
	}
}

func TestTrackerReleasesValuesWhenItEvictsAKey(t *testing.T) {
	tracker := NewTracker(time.Minute, 1)
	base := time.Unix(1_800_000_000, 0)
	tracker.addAt("source-0", "one", base, 0)
	tracker.addAt("source-0", "two", base, 0)
	tracker.addAt("source-1", "one", base.Add(time.Second), 0)

	if len(tracker.entries) != 1 || tracker.values != 1 {
		t.Fatalf("key eviction left stale state: keys=%d values=%d", len(tracker.entries), tracker.values)
	}
	if _, exists := tracker.entries["source-1"]; !exists {
		t.Fatal("new source did not replace the evicted source")
	}
}

func TestTrackerFiresOncePerThresholdEpisodeAndRearmsAfterExpiry(t *testing.T) {
	tracker := NewTracker(10*time.Second, 4)
	base := time.Unix(1_800_000_000, 0)

	for _, value := range []string{"22", "80"} {
		if count, crossed, _ := tracker.addAt("source-target", value, base, 3); count >= 3 || crossed {
			t.Fatalf("sub-threshold value %q: count=%d crossed=%t", value, count, crossed)
		}
	}
	count, crossed, values := tracker.addAt("source-target", "443", base, 3)
	if count != 3 || !crossed || len(values) != 3 {
		t.Fatalf("first threshold crossing: count=%d crossed=%t values=%v", count, crossed, values)
	}
	if count, crossed, _ := tracker.addAt("source-target", "8443", base, 3); count != 4 || crossed {
		t.Fatalf("same episode: count=%d crossed=%t", count, crossed)
	}

	next := base.Add(11 * time.Second)
	if count, crossed, _ := tracker.addAt("source-target", "25", next, 3); count != 1 || crossed {
		t.Fatalf("expired episode restart: count=%d crossed=%t", count, crossed)
	}
	tracker.addAt("source-target", "465", next, 3)
	count, crossed, values = tracker.addAt("source-target", "993", next, 3)
	if count != 3 || !crossed || len(values) != 3 {
		t.Fatalf("new episode threshold crossing: count=%d crossed=%t values=%v", count, crossed, values)
	}
}
