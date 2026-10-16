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
		tracker:   state.NewTracker(window, state.MaxTrackerKeys),
		threshold: threshold,
	}
}

func (d *BruteForce) Check(r flow.FlowRecord) *Detection {
	dstIP := r.EffectiveDstIP()
	dstPort := r.EffectiveDstPort()
	portString := strconv.Itoa(int(dstPort))
	// Key is (external_src, effective dst_port): count distinct internal hosts.
	key := r.SrcIP.String() + ":" + portString
	count := d.tracker.Add(key, dstIP.String())
	if count < d.threshold {
		return nil
	}
	// DstIP intentionally nil — dedup collapses repeated alerts for the same
	// (src, port) spray to one per refire window. Port is preserved in DstPort.
	return &Detection{
		Type:       "brute_force",
		Severity:   SeverityHigh,
		Confidence: thresholdConfidence(count, d.threshold),
		Reason:     ReasonInboundServiceSpray,
		SrcIP:      r.SrcIP,
		DstPort:    r.DstPort,
		Message:    fmt.Sprintf("%s attempted port %d on %d distinct internal hosts", r.SrcIP, dstPort, count),
		At:         r.SeenAt,
	}
}

func (d *BruteForce) Prune() { d.tracker.Prune() }
