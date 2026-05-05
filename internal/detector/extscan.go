package detector

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
	"github.com/ecan0/serpent-wrt/internal/state"
)

// ExtScan detects external hosts that probe many distinct ports on a single
// internal host — inbound reconnaissance / port scanning from WAN.
type ExtScan struct {
	tracker   *state.Tracker
	threshold int
}

func NewExtScan(threshold int, window time.Duration) *ExtScan {
	return &ExtScan{
		tracker:   state.NewTracker(window, 1024),
		threshold: threshold,
	}
}

func (d *ExtScan) Check(r flow.FlowRecord) *Detection {
	portStr := strconv.Itoa(int(r.DstPort))
	// Key is (external_src, internal_dst): count distinct ports per target host.
	key := r.SrcIP.String() + ":" + r.DstIP.String()
	count := d.tracker.Add(key, portStr)
	if count < d.threshold {
		return nil
	}
	return &Detection{
		Type:       "ext_scan",
		Severity:   SeverityMedium,
		Confidence: thresholdConfidence(count, d.threshold),
		Reason:     ReasonInboundDistinctPorts,
		SrcIP:      r.SrcIP,
		DstIP:      r.DstIP,
		DstPort:    r.DstPort,
		Message:    fmt.Sprintf("%s scanned %d distinct ports on internal host %s", r.SrcIP, count, r.DstIP),
		At:         time.Now(),
	}
}

func (d *ExtScan) Prune() { d.tracker.Prune() }
