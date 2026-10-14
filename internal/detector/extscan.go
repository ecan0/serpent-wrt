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
		tracker:   state.NewTracker(window, state.MaxTrackerKeys),
		threshold: threshold,
	}
}

func (d *ExtScan) Check(r flow.FlowRecord) *Detection {
	dstIP := r.EffectiveDstIP()
	dstPort := r.EffectiveDstPort()
	portString := strconv.Itoa(int(dstPort))
	// An external source and effective internal host share one scan episode.
	key := r.SrcIP.String() + ":" + dstIP.String()
	count, crossed, values := d.tracker.AddThreshold(key, portString, d.threshold)
	if !crossed {
		return nil
	}
	ports := observedPorts(values)
	return &Detection{
		Type:              "ext_scan",
		Severity:          SeverityMedium,
		Confidence:        thresholdConfidence(count, d.threshold),
		Reason:            ReasonInboundDistinctPorts,
		SrcIP:             r.SrcIP,
		DstIP:             r.DstIP,
		DstPort:           r.DstPort,
		DistinctPortCount: count,
		ObservedDstPorts:  ports,
		Message:           fmt.Sprintf("%s scanned %d distinct ports on internal host %s (threshold %d)", r.SrcIP, count, dstIP, d.threshold),
		At:                r.SeenAt,
	}
}

func (d *ExtScan) Prune() { d.tracker.Prune() }
