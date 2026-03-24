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
	if !isBeaconing(times, 2*time.Second) {
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
	if isBeaconing(times, 2*time.Second) {
		t.Fatal("expected no beaconing for irregular intervals")
	}
}

func TestIsBeaconingTooFewPoints(t *testing.T) {
	base := time.Now()
	if isBeaconing([]time.Time{base}, 2*time.Second) {
		t.Fatal("single timestamp should not trigger beaconing")
	}
	if isBeaconing([]time.Time{}, 2*time.Second) {
		t.Fatal("empty slice should not trigger beaconing")
	}
}
