package detector

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
)

// Beacon detects hosts that initiate periodic connections to the same
// destination — a pattern characteristic of C2 check-in behavior.
//
// Only non-ESTABLISHED TCP flows and UDP flows are examined; persistent
// long-lived connections are excluded to avoid false positives.
type Beacon struct {
	mu         sync.Mutex
	entries    map[string]*beaconEntry
	window     time.Duration
	minHits    int
	tolerance  time.Duration
	maxEntries int
}

type beaconEntry struct {
	times   []time.Time
	expires time.Time
}

func NewBeacon(minHits int, tolerance, window time.Duration) *Beacon {
	return &Beacon{
		entries:    make(map[string]*beaconEntry),
		window:     window,
		minHits:    minHits,
		tolerance:  tolerance,
		maxEntries: 512,
	}
}

func (d *Beacon) Check(r flow.FlowRecord) *Detection {
	// Skip persistent connections — beaconing is about repeated initiation.
	if r.Proto == "tcp" && r.State == "ESTABLISHED" {
		return nil
	}

	key := r.SrcIP.String() + ":" + r.DstIP.String()
	now := time.Now()
	cutoff := now.Add(-d.window)

	d.mu.Lock()
	e, ok := d.entries[key]
	if !ok {
		if len(d.entries) >= d.maxEntries {
			d.evictOldestLocked(now)
		}
		e = &beaconEntry{expires: now.Add(d.window)}
		d.entries[key] = e
	}
	e.times = append(e.times, now)
	e.expires = now.Add(d.window)
	e.times = trimBefore(e.times, cutoff)
	times := make([]time.Time, len(e.times))
	copy(times, e.times)
	d.mu.Unlock()

	if len(times) < d.minHits {
		return nil
	}
	if !isBeaconing(times, d.tolerance) {
		return nil
	}
	return &Detection{
		Type:    "beacon",
		SrcIP:   r.SrcIP,
		DstIP:   r.DstIP,
		DstPort: r.DstPort,
		Message: fmt.Sprintf("%s beaconing to %s (%d observations in window)", r.SrcIP, r.DstIP, len(times)),
		At:      now,
	}
}

func (d *Beacon) Prune() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, e := range d.entries {
		if now.After(e.expires) {
			delete(d.entries, k)
		}
	}
}

func (d *Beacon) evictOldestLocked(now time.Time) {
	var oldest string
	var oldestExp time.Time
	for k, e := range d.entries {
		if oldest == "" || e.expires.Before(oldestExp) {
			oldest = k
			oldestExp = e.expires
		}
	}
	if oldest != "" {
		delete(d.entries, oldest)
	}
}

// isBeaconing returns true when the timestamp sequence shows a regular
// inter-arrival interval with standard deviation within tolerance.
func isBeaconing(times []time.Time, tolerance time.Duration) bool {
	if len(times) < 2 {
		return false
	}
	sorted := make([]time.Time, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	intervals := make([]float64, len(sorted)-1)
	var sum float64
	for i := 1; i < len(sorted); i++ {
		iv := float64(sorted[i].Sub(sorted[i-1]))
		intervals[i-1] = iv
		sum += iv
	}
	mean := sum / float64(len(intervals))

	var variance float64
	for _, iv := range intervals {
		d := iv - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance / float64(len(intervals)))
	return stddev <= float64(tolerance)
}

func trimBefore(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}
