package flow

import (
	"net"
	"time"
)

// FlowRecord is a compact normalized representation of a conntrack entry.
// The original tuple is stored in SrcIP/DstIP and SrcPort/DstPort. Reply
// fields preserve the conntrack reply tuple when a snapshot provides it.
type FlowRecord struct {
	Proto        string // "tcp" or "udp"
	SrcIP        net.IP
	DstIP        net.IP
	SrcPort      uint16
	DstPort      uint16
	State        string // TCP state (e.g. "ESTABLISHED", "SYN_SENT") or empty for UDP
	SeenAt       time.Time
	ReplySrcIP   net.IP
	ReplyDstIP   net.IP
	ReplySrcPort uint16
	ReplyDstPort uint16
}

// EffectiveDstIP returns the internal endpoint when the conntrack reply tuple
// identifies a translated destination. Otherwise it returns the original dst.
func (r FlowRecord) EffectiveDstIP() net.IP {
	if r.ReplySrcIP != nil {
		return r.ReplySrcIP
	}
	return r.DstIP
}

// EffectiveDstPort returns the translated service port when present.
func (r FlowRecord) EffectiveDstPort() uint16 {
	if r.ReplySrcIP != nil {
		return r.ReplySrcPort
	}
	return r.DstPort
}

// TranslatedDst returns the translated destination only when the reply tuple
// differs from the original destination tuple.
func (r FlowRecord) TranslatedDst() (net.IP, uint16, bool) {
	if r.ReplySrcIP == nil ||
		(r.ReplySrcIP.Equal(r.DstIP) && r.ReplySrcPort == r.DstPort) {
		return nil, 0, false
	}
	return r.ReplySrcIP, r.ReplySrcPort, true
}
