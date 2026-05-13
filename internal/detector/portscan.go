package detector

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ecan0/serpent-wrt/internal/flow"
	"github.com/ecan0/serpent-wrt/internal/state"
)

// PortScan detects hosts that attempt connections to an unusually large number
// of distinct destination ports within a rolling time window.
type PortScan struct {
	tracker   *state.Tracker
	threshold int
}

func NewPortScan(threshold int, window time.Duration) *PortScan {
	return &PortScan{
		tracker:   state.NewTracker(window, 1024),
		threshold: threshold,
	}
}

func (d *PortScan) Check(r flow.FlowRecord) *Detection {
	portStr := strconv.Itoa(int(r.DstPort))
	// Key is (src, dst) so we count distinct ports to a specific target host.
	key := r.SrcIP.String() + ":" + r.DstIP.String()
	count := d.tracker.Add(key, portStr)
	if count < d.threshold {
		return nil
	}
	return &Detection{
		Type:       "port_scan",
		Severity:   SeverityMedium,
		Confidence: thresholdConfidence(count, d.threshold),
		Reason:     ReasonOutboundDistinctPorts,
		SrcIP:      r.SrcIP,
		DstIP:      r.DstIP,
		DstPort:    r.DstPort,
		Message:    fmt.Sprintf("%s scanned %d distinct ports on %s (threshold %d)", r.SrcIP, count, r.DstIP, d.threshold),
		At:         time.Now(),
	}
}

func (d *PortScan) Prune() { d.tracker.Prune() }
