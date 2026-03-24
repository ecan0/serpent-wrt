package flow

import (
	"net"
	"time"
)

// FlowRecord is a compact normalized representation of a conntrack entry.
// Only the forward direction (originating side) is captured.
type FlowRecord struct {
	Proto   string // "tcp" or "udp"
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	State   string // TCP state (e.g. "ESTABLISHED", "SYN_SENT") or empty for UDP
	SeenAt  time.Time
}
