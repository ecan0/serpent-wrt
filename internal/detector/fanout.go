package detector

import (
	"fmt"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
	"github.com/ecan0/serpent-wrt/internal/state"
)

// Fanout detects hosts that contact an unusually large number of distinct
// external destinations within a rolling time window — a pattern consistent
// with scanning, DDoS participation, or worm propagation.
type Fanout struct {
	tracker   *state.Tracker
	threshold int
}

func NewFanout(threshold int, window time.Duration) *Fanout {
	return &Fanout{
		tracker:   state.NewTracker(window, 1024),
		threshold: threshold,
	}
}

func (d *Fanout) Check(r flow.FlowRecord) *Detection {
	count := d.tracker.Add(r.SrcIP.String(), r.DstIP.String())
	if count < d.threshold {
		return nil
	}
	return &Detection{
		Type:    "fanout",
		SrcIP:   r.SrcIP,
		DstIP:   r.DstIP,
		Message: fmt.Sprintf("%s contacted %d distinct destinations (threshold %d)", r.SrcIP, count, d.threshold),
		At:      time.Now(),
	}
}

func (d *Fanout) Prune() { d.tracker.Prune() }
