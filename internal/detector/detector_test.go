package detector_test

import (
	"net"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/detector"
	"github.com/ecan0/serpent-wrt/internal/feed"
	"github.com/ecan0/serpent-wrt/internal/flow"
)

func makeFlow(src, dst string, dstPort uint16, state string) flow.FlowRecord {
	return flow.FlowRecord{
		Proto:   "tcp",
		SrcIP:   net.ParseIP(src),
		DstIP:   net.ParseIP(dst),
		DstPort: dstPort,
		State:   state,
		SeenAt:  time.Now(),
	}
}

// --- FeedMatch ---

func TestFeedMatchHit(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load feed: %v", err)
	}
	d := detector.NewFeedMatch(f)

	det := d.Check(makeFlow("192.168.1.1", "1.2.3.4", 443, "SYN_SENT"))
	if det == nil {
		t.Fatal("expected detection for 1.2.3.4 (in feed)")
	}
	if det.Type != "feed_match" {
		t.Errorf("type: got %q, want feed_match", det.Type)
	}
}

func TestFeedMatchCIDR(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load feed: %v", err)
	}
	d := detector.NewFeedMatch(f)

	// 5.6.7.100 is within 5.6.7.0/24
	det := d.Check(makeFlow("192.168.1.1", "5.6.7.100", 80, "SYN_SENT"))
	if det == nil {
		t.Fatal("expected detection for 5.6.7.100 (in CIDR 5.6.7.0/24)")
	}
}

func TestFeedMatchMiss(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load feed: %v", err)
	}
	d := detector.NewFeedMatch(f)

	det := d.Check(makeFlow("192.168.1.1", "9.9.9.9", 53, "SYN_SENT"))
	if det != nil {
		t.Fatal("unexpected detection for 9.9.9.9 (not in feed)")
	}
}

// --- Fanout ---

func TestFanoutThreshold(t *testing.T) {
	d := detector.NewFanout(3, 10*time.Second)
	src := "192.168.1.1"

	if det := d.Check(makeFlow(src, "1.1.1.1", 80, "")); det != nil {
		t.Fatal("unexpected detection before threshold")
	}
	if det := d.Check(makeFlow(src, "2.2.2.2", 80, "")); det != nil {
		t.Fatal("unexpected detection before threshold")
	}
	det := d.Check(makeFlow(src, "3.3.3.3", 80, ""))
	if det == nil {
		t.Fatal("expected detection at threshold 3")
	}
	if det.Type != "fanout" {
		t.Errorf("type: got %q, want fanout", det.Type)
	}
}

func TestFanoutDuplicateDst(t *testing.T) {
	d := detector.NewFanout(3, 10*time.Second)
	src := "192.168.1.2"

	// Same destination repeated — should not increase distinct count.
	d.Check(makeFlow(src, "1.1.1.1", 80, ""))
	d.Check(makeFlow(src, "1.1.1.1", 80, ""))
	det := d.Check(makeFlow(src, "1.1.1.1", 80, ""))
	if det != nil {
		t.Fatal("unexpected detection for repeated same destination")
	}
}

// --- PortScan ---

func TestPortScanThreshold(t *testing.T) {
	d := detector.NewPortScan(3, 10*time.Second)
	src, dst := "192.168.1.1", "10.0.0.1"

	d.Check(makeFlow(src, dst, 22, ""))
	d.Check(makeFlow(src, dst, 80, ""))
	det := d.Check(makeFlow(src, dst, 443, ""))
	if det == nil {
		t.Fatal("expected detection at threshold 3")
	}
	if det.Type != "port_scan" {
		t.Errorf("type: got %q, want port_scan", det.Type)
	}
}

func TestPortScanDuplicatePort(t *testing.T) {
	d := detector.NewPortScan(3, 10*time.Second)
	src, dst := "192.168.1.2", "10.0.0.2"

	d.Check(makeFlow(src, dst, 80, ""))
	d.Check(makeFlow(src, dst, 80, ""))
	det := d.Check(makeFlow(src, dst, 80, ""))
	if det != nil {
		t.Fatal("unexpected detection for repeated same port")
	}
}

// --- Prune ---

func TestFanoutPruneNoPanic(t *testing.T) {
	d := detector.NewFanout(3, 10*time.Second)
	src := "192.168.1.5"
	d.Check(makeFlow(src, "1.1.1.1", 80, ""))
	d.Check(makeFlow(src, "2.2.2.2", 80, ""))
	d.Prune() // must not panic
}

func TestPortScanPruneNoPanic(t *testing.T) {
	d := detector.NewPortScan(3, 10*time.Second)
	src, dst := "192.168.1.5", "10.0.0.5"
	d.Check(makeFlow(src, dst, 22, ""))
	d.Check(makeFlow(src, dst, 80, ""))
	d.Prune() // must not panic
}

func TestBeaconPruneNoPanic(t *testing.T) {
	d := detector.NewBeacon(5, 2*time.Second, 5*time.Minute)
	d.Check(makeFlow("192.168.1.1", "1.2.3.4", 443, "SYN_SENT"))
	d.Prune() // must not panic
}

// --- Beacon edge cases ---

func TestBeaconSkipsEstablished(t *testing.T) {
	d := detector.NewBeacon(2, 2*time.Second, time.Minute)
	// ESTABLISHED TCP flows should be skipped — they represent persistent connections,
	// not repeated beacon initiations.
	for i := 0; i < 10; i++ {
		det := d.Check(makeFlow("192.168.1.1", "1.2.3.4", 443, "ESTABLISHED"))
		if det != nil {
			t.Fatal("beacon should not fire on ESTABLISHED flows")
		}
	}
}

func TestFeedMatchNilDst(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load feed: %v", err)
	}
	d := detector.NewFeedMatch(f)
	r := flow.FlowRecord{
		Proto:  "tcp",
		SrcIP:  net.ParseIP("192.168.1.1"),
		DstIP:  nil,
		SeenAt: time.Now(),
	}
	// nil DstIP must not panic and must return no detection.
	if det := d.Check(r); det != nil {
		t.Fatal("expected nil detection for nil DstIP")
	}
}
