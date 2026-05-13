package detector

import (
	"testing"
	"time"
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
