// Package detector implements flow-based threat detectors.
// Each detector examines a FlowRecord and returns a Detection when a
// heuristic threshold is crossed, or nil if nothing is triggered.
package detector

import (
	"net"
	"time"
)

// Detection represents a triggered heuristic event.
type Detection struct {
	Type    string // detector name: "feed_match", "fanout", "port_scan", "beacon"
	SrcIP   net.IP
	DstIP   net.IP
	DstPort uint16
	Message string
	At      time.Time
}
