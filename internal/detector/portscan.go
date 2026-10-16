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
		tracker:   state.NewTracker(window, state.MaxTrackerKeys),
		threshold: threshold,
	}
}

func (d *PortScan) Check(r flow.FlowRecord) *Detection {
	dstIP := r.EffectiveDstIP()
	dstPort := r.EffectiveDstPort()
	portString := strconv.Itoa(int(dstPort))
	// A source and effective destination share one scan episode.
	key := r.SrcIP.String() + ":" + dstIP.String()
	count, crossed, values := d.tracker.AddThreshold(key, portString, d.threshold)
	if !crossed {
		return nil
	}
	ports := observedPorts(values)
	return &Detection{
		Type:              "port_scan",
		Severity:          SeverityMedium,
		Confidence:        thresholdConfidence(count, d.threshold),
		Reason:            ReasonOutboundDistinctPorts,
		SrcIP:             r.SrcIP,
		DstIP:             r.DstIP,
		DstPort:           r.DstPort,
		DistinctPortCount: count,
		ObservedDstPorts:  ports,
		Message:           fmt.Sprintf("%s scanned %d distinct ports on %s (threshold %d)", r.SrcIP, count, dstIP, d.threshold),
		At:                r.SeenAt,
	}
}

func (d *PortScan) Prune() { d.tracker.Prune() }
