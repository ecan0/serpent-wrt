package runtime

import (
	"net"

	"github.com/ecan0/serpent-wrt/internal/collector"
	"github.com/ecan0/serpent-wrt/internal/flow"
)

type flowTuple struct {
	proto   string
	src     [16]byte
	dst     [16]byte
	srcPort uint16
	dstPort uint16
}

type snapshotTracker struct {
	previous    map[flowTuple]struct{}
	current     map[flowTuple]struct{}
	added       []flow.FlowRecord
	initialized bool
}

func newSnapshotTracker() *snapshotTracker {
	return &snapshotTracker{
		previous: make(map[flowTuple]struct{}),
		current:  make(map[flowTuple]struct{}),
	}
}

// observe returns only tuples that appeared since the last complete snapshot.
// It treats the first snapshot as a baseline. If a snapshot exceeds the fixed
// capacity, it clears history and waits for a complete baseline before it
// reports more new tuples.
func (t *snapshotTracker) observe(records []flow.FlowRecord) ([]flow.FlowRecord, bool) {
	if len(records) > collector.MaxSnapshotFlows {
		clear(t.previous)
		clear(t.current)
		t.added = t.added[:0]
		t.initialized = false
		return nil, true
	}

	clear(t.current)
	t.added = t.added[:0]
	for _, record := range records {
		key := makeFlowTuple(record)
		if _, duplicate := t.current[key]; duplicate {
			continue
		}
		t.current[key] = struct{}{}
		if t.initialized {
			if _, known := t.previous[key]; !known {
				t.added = append(t.added, record)
			}
		}
	}
	t.previous, t.current = t.current, t.previous
	t.initialized = true
	return t.added, false
}

func makeFlowTuple(record flow.FlowRecord) flowTuple {
	key := flowTuple{
		proto:   record.Proto,
		srcPort: record.SrcPort,
		dstPort: record.DstPort,
	}
	copy(key.src[:], canonicalIP(record.SrcIP))
	copy(key.dst[:], canonicalIP(record.DstIP))
	return key
}

func canonicalIP(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}
