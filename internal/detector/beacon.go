package detector

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
	"github.com/ecan0/serpent-wrt/internal/state"
)

// Beacon detects hosts that initiate periodic connections to the same
// destination — a pattern characteristic of C2 check-in behavior.
//
// Only non-ESTABLISHED TCP flows and UDP flows are examined; persistent
// long-lived connections are excluded to avoid false positives.
type Beacon struct {
	mu           sync.Mutex
	entries      map[string]*beaconEntry
	window       time.Duration
	minHits      int
	tolerance    time.Duration
	minInterval  time.Duration
	excludePorts map[uint16]bool
	maxEntries   int
	samples      int
}

type beaconEntry struct {
	times   []time.Time
	expires time.Time
}

func NewBeacon(minHits int, tolerance, window, minInterval time.Duration, excludePorts []uint16) *Beacon {
	ep := make(map[uint16]bool, len(excludePorts))
	for _, p := range excludePorts {
		ep[p] = true
	}
	return &Beacon{
		entries:      make(map[string]*beaconEntry),
		window:       window,
		minHits:      minHits,
		tolerance:    tolerance,
		minInterval:  minInterval,
		excludePorts: ep,
		maxEntries:   512,
	}
}

func (d *Beacon) Check(r flow.FlowRecord) *Detection {
	if r.Proto == "tcp" && r.State == "ESTABLISHED" {
		return nil
	}
	if d.excludePorts[r.DstPort] {
		return nil
	}

	now := r.SeenAt
	if now.IsZero() {
		now = time.Now()
	}
	key := r.SrcIP.String() + ":" + r.DstIP.String()
	cutoff := now.Add(-d.window)

	d.mu.Lock()
	entry, ok := d.entries[key]
	if !ok {
		if d.samples >= state.MaxSamplesTotal {
			d.mu.Unlock()
			return nil
		}
		if len(d.entries) >= d.maxEntries {
			d.evictOldestLocked()
		}
		entry = &beaconEntry{}
		d.entries[key] = entry
	} else {
		kept := trimBefore(entry.times, cutoff)
		d.samples -= len(entry.times) - len(kept)
		entry.times = kept
	}

	if len(entry.times) >= state.MaxSamplesPerKey || d.samples >= state.MaxSamplesTotal {
		d.mu.Unlock()
		return nil
	}
	entry.times = append(entry.times, now)
	entry.expires = now.Add(d.window)
	d.samples++
	if len(entry.times) < d.minHits {
		d.mu.Unlock()
		return nil
	}
	times := append([]time.Time(nil), entry.times...)
	d.mu.Unlock()

	ok, confidence := beaconScore(times, d.tolerance, d.minInterval)
	if !ok {
		return nil
	}
	if len(times) >= d.minHits+2 && confidence < 95 {
		confidence += 3
		if confidence > 95 {
			confidence = 95
		}
	}
	return &Detection{
		Type:       "beacon",
		Severity:   SeverityHigh,
		Confidence: confidence,
		Reason:     ReasonBeaconCadence,
		SrcIP:      r.SrcIP,
		DstIP:      r.DstIP,
		DstPort:    r.DstPort,
		Message:    fmt.Sprintf("%s beaconing to %s (%d observations in window)", r.SrcIP, r.DstIP, len(times)),
		At:         now,
	}
}

func (d *Beacon) Prune() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, entry := range d.entries {
		if now.After(entry.expires) {
			d.samples -= len(entry.times)
			delete(d.entries, key)
		}
	}
}

func (d *Beacon) evictOldestLocked() {
	var oldest string
	var oldestExp time.Time
	for key, entry := range d.entries {
		if oldest == "" || entry.expires.Before(oldestExp) {
			oldest = key
			oldestExp = entry.expires
		}
	}
	if oldest != "" {
		d.samples -= len(d.entries[oldest].times)
		delete(d.entries, oldest)
	}
}

// isBeaconing returns true when the timestamp sequence shows a regular
// inter-arrival interval with standard deviation within tolerance.
func isBeaconing(times []time.Time, tolerance, minInterval time.Duration) bool {
	ok, _ := beaconScore(times, tolerance, minInterval)
	return ok
}

func beaconScore(times []time.Time, tolerance, minInterval time.Duration) (bool, uint8) {
	if len(times) < 2 {
		return false, 0
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

	// Reject burst traffic — real beaconing has intervals of seconds/minutes.
	if time.Duration(mean) < minInterval {
		return false, 0
	}

	var variance float64
	for _, iv := range intervals {
		d := iv - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance / float64(len(intervals)))
	if stddev > float64(tolerance) {
		return false, 0
	}
	if tolerance <= 0 {
		return true, 80
	}
	ratio := stddev / float64(tolerance)
	switch {
	case ratio <= 0.25:
		return true, 95
	case ratio <= 0.50:
		return true, 90
	case ratio <= 0.75:
		return true, 82
	default:
		return true, 72
	}
}

func trimBefore(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}
