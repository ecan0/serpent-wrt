package detector

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
	"github.com/ecan0/serpent-wrt/internal/state"
)

// BruteForce detects external hosts that attempt connections to the same
// service port across many distinct internal hosts — horizontal service
// scanning / credential stuffing from WAN.
type BruteForce struct {
	tracker   *state.Tracker
	threshold int
}

func NewBruteForce(threshold int, window time.Duration) *BruteForce {
	return &BruteForce{
		tracker:   state.NewTracker(window, 1024),
		threshold: threshold,
	}
}

func (d *BruteForce) Check(r flow.FlowRecord) *Detection {
	portStr := strconv.Itoa(int(r.DstPort))
	// Key is (external_src, dst_port): count distinct internal hosts targeted.
	key := r.SrcIP.String() + ":" + portStr
	count := d.tracker.Add(key, r.DstIP.String())
	if count < d.threshold {
		return nil
	}
	// DstIP intentionally nil — dedup collapses repeated alerts for the same
	// (src, port) spray to one per refire window. Port is preserved in DstPort.
	return &Detection{
		Type:    "brute_force",
		SrcIP:   r.SrcIP,
		DstPort: r.DstPort,
		Message: fmt.Sprintf("%s attempted port %d on %d distinct internal hosts", r.SrcIP, r.DstPort, count),
		At:      time.Now(),
	}
}

func (d *BruteForce) Prune() { d.tracker.Prune() }
