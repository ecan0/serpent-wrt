package detector

import (
	"net"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
	"github.com/ecan0/serpent-wrt/internal/state"
)

func TestIsBeaconingRegular(t *testing.T) {
	base := time.Now()
	times := []time.Time{
		base,
		base.Add(10 * time.Second),
		base.Add(20 * time.Second),
		base.Add(30 * time.Second),
		base.Add(40 * time.Second),
	}
	if !isBeaconing(times, 2*time.Second, 1*time.Second) {
		t.Fatal("expected beaconing for regular 10s intervals with 2s tolerance")
	}
}

func TestIsBeaconingIrregular(t *testing.T) {
	base := time.Now()
	times := []time.Time{
		base,
		base.Add(5 * time.Second),
		base.Add(25 * time.Second), // large gap
		base.Add(30 * time.Second),
		base.Add(60 * time.Second), // large gap
	}
	if isBeaconing(times, 2*time.Second, 1*time.Second) {
		t.Fatal("expected no beaconing for irregular intervals")
	}
}

func TestIsBeaconingTooFewPoints(t *testing.T) {
	base := time.Now()
	if isBeaconing([]time.Time{base}, 2*time.Second, 1*time.Second) {
		t.Fatal("single timestamp should not trigger beaconing")
	}
	if isBeaconing([]time.Time{}, 2*time.Second, 1*time.Second) {
		t.Fatal("empty slice should not trigger beaconing")
	}
}

func TestBeaconScoreConfidenceTracksCadenceQuality(t *testing.T) {
	base := time.Now()
	tight := []time.Time{
		base,
		base.Add(10 * time.Second),
		base.Add(20 * time.Second),
		base.Add(30 * time.Second),
		base.Add(40 * time.Second),
	}
	loose := []time.Time{
		base,
		base.Add(10 * time.Second),
		base.Add(19 * time.Second),
		base.Add(31 * time.Second),
		base.Add(40 * time.Second),
	}

	tightOK, tightConfidence := beaconScore(tight, 3*time.Second, 1*time.Second)
	looseOK, looseConfidence := beaconScore(loose, 3*time.Second, 1*time.Second)
	if !tightOK || !looseOK {
		t.Fatal("expected both sequences to remain within tolerance")
	}
	if tightConfidence <= looseConfidence {
		t.Fatalf("tight cadence confidence should exceed loose cadence: tight=%d loose=%d", tightConfidence, looseConfidence)
	}
}

func TestBeaconHistoryStaysWithinPerKeyAndTotalLimits(t *testing.T) {
	d := NewBeacon(state.MaxSamplesPerKey+1, time.Second, 24*time.Hour, time.Second, nil)
	base := time.Now()
	for pair := range 128 {
		src := net.IPv4(192, 0, byte(pair/256), byte(pair%256+1))
		dst := net.IPv4(198, 51, byte(pair/256), byte(pair%256+1))
		for sample := range state.MaxSamplesPerKey {
			d.Check(flow.FlowRecord{
				Proto:   "udp",
				SrcIP:   src,
				DstIP:   dst,
				SrcPort: uint16(40000 + sample),
				DstPort: 443,
				SeenAt:  base.Add(time.Duration(pair*state.MaxSamplesPerKey+sample) * time.Second),
			})
		}
	}
	if d.samples != state.MaxSamplesTotal {
		t.Fatalf("retained samples: got %d, want cap %d", d.samples, state.MaxSamplesTotal)
	}
	for key, entry := range d.entries {
		if len(entry.times) > state.MaxSamplesPerKey {
			t.Fatalf("entry %q retains %d samples, over cap %d", key, len(entry.times), state.MaxSamplesPerKey)
		}
	}
	before := d.samples
	d.Check(flow.FlowRecord{
		Proto:   "udp",
		SrcIP:   net.ParseIP("203.0.113.1"),
		DstIP:   net.ParseIP("203.0.113.2"),
		DstPort: 443,
		SeenAt:  base.Add(3 * time.Hour),
	})
	if d.samples != before {
		t.Fatalf("sample overflow changed total: got %d, want %d", d.samples, before)
	}
}

func TestBeaconExpiryReleasesHistoryCapacity(t *testing.T) {
	d := NewBeacon(state.MaxSamplesPerKey+1, time.Second, time.Minute, time.Second, nil)
	base := time.Now()
	src, dst := net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.1")
	for sample := range state.MaxSamplesPerKey {
		d.Check(flow.FlowRecord{
			Proto:   "udp",
			SrcIP:   src,
			DstIP:   dst,
			SrcPort: uint16(40000 + sample),
			DstPort: 443,
			SeenAt:  base.Add(time.Duration(sample) * time.Second),
		})
	}
	d.Check(flow.FlowRecord{
		Proto:   "udp",
		SrcIP:   src,
		DstIP:   dst,
		DstPort: 443,
		SeenAt:  base.Add(3 * time.Minute),
	})
	if d.samples != 1 {
		t.Fatalf("expired samples not released: got %d, want 1", d.samples)
	}
}

func TestBeaconEntryLimitEvictsOldestHistory(t *testing.T) {
	d := NewBeacon(1000, time.Second, time.Hour, time.Second, nil)
	base := time.Now()
	for i := range 513 {
		recordID := i + 1
		d.Check(flow.FlowRecord{
			Proto:   "udp",
			SrcIP:   net.IPv4(192, 0, byte(recordID/254), byte(recordID%254+1)),
			DstIP:   net.IPv4(198, 51, byte(recordID/254), byte(recordID%254+1)),
			DstPort: 443,
			SeenAt:  base.Add(time.Duration(i) * time.Second),
		})
	}
	if len(d.entries) != d.maxEntries {
		t.Fatalf("retained entries: got %d, want %d", len(d.entries), d.maxEntries)
	}
	if d.samples != len(d.entries) {
		t.Fatalf("retained samples after entry eviction: got %d, want %d", d.samples, len(d.entries))
	}
}
