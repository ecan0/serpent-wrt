package runtime

import (
	"net"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/collector"
	"github.com/ecan0/serpent-wrt/internal/flow"
)

func snapshotFlow(srcPort uint16) flow.FlowRecord {
	return flow.FlowRecord{
		Proto:   "udp",
		SrcIP:   net.ParseIP("192.0.2.10"),
		DstIP:   net.ParseIP("198.51.100.20"),
		SrcPort: srcPort,
		DstPort: 443,
		SeenAt:  time.Unix(int64(srcPort), 0),
	}
}

func TestSnapshotTrackerBaselinesAndReportsOnlyNewTuples(t *testing.T) {
	tracker := newSnapshotTracker()
	old := snapshotFlow(40000)
	new := snapshotFlow(40001)

	if got, overflow := tracker.observe([]flow.FlowRecord{old}); len(got) != 0 || overflow {
		t.Fatalf("initial snapshot: got %d new tuples, overflow=%t", len(got), overflow)
	}
	if got, overflow := tracker.observe([]flow.FlowRecord{old, old}); len(got) != 0 || overflow {
		t.Fatalf("repeated snapshot: got %d new tuples, overflow=%t", len(got), overflow)
	}
	got, overflow := tracker.observe([]flow.FlowRecord{old, new})
	if overflow || len(got) != 1 || got[0].SrcPort != new.SrcPort {
		t.Fatalf("new tuple: got %#v, overflow=%t", got, overflow)
	}
}

func TestSnapshotTrackerTreatsReappearedTupleAsNew(t *testing.T) {
	tracker := newSnapshotTracker()
	record := snapshotFlow(40000)
	tracker.observe([]flow.FlowRecord{record})
	if got, overflow := tracker.observe(nil); len(got) != 0 || overflow {
		t.Fatalf("empty snapshot: got %d new tuples, overflow=%t", len(got), overflow)
	}
	got, overflow := tracker.observe([]flow.FlowRecord{record})
	if overflow || len(got) != 1 || got[0].SrcPort != record.SrcPort {
		t.Fatalf("reappeared tuple: got %#v, overflow=%t", got, overflow)
	}
}

func TestSnapshotTrackerFailsClosedAndRebaselinesAfterOverflow(t *testing.T) {
	tracker := newSnapshotTracker()
	initial := snapshotFlow(40000)
	tracker.observe([]flow.FlowRecord{initial})

	tooMany := make([]flow.FlowRecord, collector.MaxSnapshotFlows+1)
	for i := range tooMany {
		tooMany[i] = snapshotFlow(uint16(i + 1))
	}
	if got, overflow := tracker.observe(tooMany); len(got) != 0 || !overflow {
		t.Fatalf("oversized snapshot: got %d new tuples, overflow=%t", len(got), overflow)
	}

	baseline := snapshotFlow(50000)
	if got, overflow := tracker.observe([]flow.FlowRecord{baseline}); len(got) != 0 || overflow {
		t.Fatalf("post-overflow baseline: got %d new tuples, overflow=%t", len(got), overflow)
	}
	new := snapshotFlow(50001)
	got, overflow := tracker.observe([]flow.FlowRecord{baseline, new})
	if overflow || len(got) != 1 || got[0].SrcPort != new.SrcPort {
		t.Fatalf("new tuple after rebaseline: got %#v, overflow=%t", got, overflow)
	}
}

func TestSnapshotTrackerUsesCanonicalIPv4TupleBytes(t *testing.T) {
	left := snapshotFlow(40000)
	right := left
	right.SrcIP = left.SrcIP.To4()
	if makeFlowTuple(left) != makeFlowTuple(right) {
		t.Fatal("IPv4 tuple identity changed with the net.IP representation")
	}
}
