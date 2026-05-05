// Package detector implements flow-based threat detectors.
// Each detector examines a FlowRecord and returns a Detection when a
// heuristic threshold is crossed, or nil if nothing is triggered.
package detector

import (
	"net"
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

// Detection represents a triggered heuristic event.
type Detection struct {
	Type       string // detector name, e.g. "feed_match", "fanout", "port_scan"
	Severity   Severity
	Confidence uint8 // 0-100 confidence score for the detector's current signal
	Reason     Reason
	SrcIP      net.IP
	DstIP      net.IP
	DstPort    uint16
	Message    string
	At         time.Time
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
