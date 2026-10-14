// Package detector implements flow-based threat detectors.
// Each detector examines a FlowRecord and returns a Detection at its threshold, or nil otherwise.
package detector

import (
	"net"
	"sort"
	"strconv"
	"time"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Reason string

const (
	ReasonHeuristicMatch               Reason = "heuristic_match"
	ReasonThreatFeedDestination        Reason = "threat_feed_destination"
	ReasonThreatFeedSource             Reason = "threat_feed_source"
	ReasonOutboundDistinctDestinations Reason = "outbound_distinct_destinations"
	ReasonOutboundDistinctPorts        Reason = "outbound_distinct_ports"
	ReasonBeaconCadence                Reason = "regular_connection_cadence"
	ReasonInboundDistinctPorts         Reason = "inbound_distinct_ports"
	ReasonInboundServiceSpray          Reason = "inbound_service_spray"
)

// Detection represents a triggered heuristic event. DstIP and DstPort retain
// the original conntrack destination. Translated destination fields preserve
// the DNAT endpoint. Scan detections include their count and observed ports.
type Detection struct {
	Type              string
	Severity          Severity
	Confidence        uint8
	Reason            Reason
	SrcIP             net.IP
	DstIP             net.IP
	DstPort           uint16
	TranslatedDstIP   net.IP
	TranslatedDstPort uint16
	DistinctPortCount int
	ObservedDstPorts  []uint16
	Message           string
	At                time.Time
}

func observedPorts(values []string) []uint16 {
	ports := make([]uint16, 0, len(values))
	for _, value := range values {
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			continue
		}
		ports = append(ports, uint16(parsed))
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

// Normalize fills metadata defaults for tests or future detectors that construct
// a Detection manually. Detector implementations should set these explicitly.
func (d *Detection) Normalize() {
	if d.Severity == "" {
		d.Severity = SeverityMedium
	}
	if d.Confidence == 0 {
		d.Confidence = 50
	}
	if d.Reason == "" {
		d.Reason = ReasonHeuristicMatch
	}
}

func thresholdConfidence(count, threshold int) uint8 {
	if threshold <= 0 {
		return 50
	}
	switch {
	case count >= threshold*2:
		return 95
	case count*10 >= threshold*15:
		return 88
	case count*10 >= threshold*12:
		return 80
	default:
		return 70
	}
}
