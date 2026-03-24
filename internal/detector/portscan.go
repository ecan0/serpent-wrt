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
	count := d.tracker.Add(r.SrcIP.String(), portStr)
	if count < d.threshold {
		return nil
	}
	return &Detection{
		Type:    "port_scan",
		SrcIP:   r.SrcIP,
		DstIP:   r.DstIP,
		DstPort: r.DstPort,
		Message: fmt.Sprintf("%s scanned %d distinct ports (threshold %d)", r.SrcIP, count, d.threshold),
		At:      time.Now(),
	}
}

func (d *PortScan) Prune() { d.tracker.Prune() }
