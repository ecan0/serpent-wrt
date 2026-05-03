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
	// DstIP must be nil so dedup collapses repeated alerts to one per src.
	if det.DstIP != nil {
		t.Errorf("fanout DstIP should be nil for dedup collapse, got %v", det.DstIP)
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
	d := detector.NewBeacon(5, 2*time.Second, 5*time.Minute, 1*time.Second, nil)
	d.Check(makeFlow("192.168.1.1", "1.2.3.4", 443, "SYN_SENT"))
	d.Prune() // must not panic
}

// --- Beacon edge cases ---

func TestBeaconSkipsEstablished(t *testing.T) {
	d := detector.NewBeacon(2, 2*time.Second, time.Minute, 1*time.Second, nil)
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

func TestFeedMatchInboundSrc(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load feed: %v", err)
	}
	d := detector.NewFeedMatch(f)
	// Known-bad IP is now the SOURCE (inbound flow).
	det := d.Check(makeFlow("1.2.3.4", "192.168.1.100", 80, "SYN_SENT"))
	if det == nil {
		t.Fatal("expected detection when src_ip is in feed")
	}
	if det.Type != "feed_match" {
		t.Errorf("type: got %q, want feed_match", det.Type)
	}
}

// --- PortScan per-dst ---

func TestPortScanDistinctTargets(t *testing.T) {
	d := detector.NewPortScan(3, 10*time.Second)
	src := "192.168.1.1"

	// Ports on dst1 — should trigger.
	d.Check(makeFlow(src, "10.0.0.1", 22, ""))
	d.Check(makeFlow(src, "10.0.0.1", 80, ""))
	det := d.Check(makeFlow(src, "10.0.0.1", 443, ""))
	if det == nil {
		t.Fatal("expected detection scanning same dst")
	}

	// Same ports on a different dst — separate counter, no detection yet.
	d2 := detector.NewPortScan(3, 10*time.Second)
	d2.Check(makeFlow(src, "10.0.0.1", 22, ""))
	d2.Check(makeFlow(src, "10.0.0.1", 80, ""))
	det2 := d2.Check(makeFlow(src, "10.0.0.2", 443, ""))
	if det2 != nil {
		t.Fatal("port scan across different dsts should not merge counts")
	}
}

// --- ExtScan ---

func TestExtScanThreshold(t *testing.T) {
	d := detector.NewExtScan(3, 10*time.Second)
	ext, target := "1.2.3.4", "192.168.1.10"

	d.Check(makeFlow(ext, target, 22, ""))
	d.Check(makeFlow(ext, target, 80, ""))
	det := d.Check(makeFlow(ext, target, 443, ""))
	if det == nil {
		t.Fatal("expected ext_scan detection at threshold")
	}
	if det.Type != "ext_scan" {
		t.Errorf("type: got %q, want ext_scan", det.Type)
	}
}

func TestExtScanDifferentTargets(t *testing.T) {
	d := detector.NewExtScan(3, 10*time.Second)
	ext := "1.2.3.4"

	// Ports spread across two targets — each counter is independent.
	d.Check(makeFlow(ext, "192.168.1.10", 22, ""))
	d.Check(makeFlow(ext, "192.168.1.11", 80, ""))
	det := d.Check(makeFlow(ext, "192.168.1.12", 443, ""))
	if det != nil {
		t.Fatal("ext_scan across different targets should not merge counts")
	}
}

func TestExtScanPruneNoPanic(t *testing.T) {
	d := detector.NewExtScan(3, 10*time.Second)
	d.Check(makeFlow("1.2.3.4", "192.168.1.10", 22, ""))
	d.Prune()
}

// --- BruteForce ---

func TestBruteForceThreshold(t *testing.T) {
	d := detector.NewBruteForce(3, 10*time.Second)
	ext := "1.2.3.4"

	d.Check(makeFlow(ext, "192.168.1.1", 22, ""))
	d.Check(makeFlow(ext, "192.168.1.2", 22, ""))
	det := d.Check(makeFlow(ext, "192.168.1.3", 22, ""))
	if det == nil {
		t.Fatal("expected brute_force detection at threshold")
	}
	if det.Type != "brute_force" {
		t.Errorf("type: got %q, want brute_force", det.Type)
	}
	// DstIP must be nil so dedup collapses spray alerts to one per (src, port).
	if det.DstIP != nil {
		t.Errorf("brute_force DstIP should be nil for dedup collapse, got %v", det.DstIP)
	}
	if det.DstPort != 22 {
		t.Errorf("brute_force DstPort should be 22, got %d", det.DstPort)
	}
}

func TestBruteForceDifferentPorts(t *testing.T) {
	d := detector.NewBruteForce(3, 10*time.Second)
	ext := "1.2.3.4"

	// Same target, different ports — different counters, no detection.
	d.Check(makeFlow(ext, "192.168.1.1", 22, ""))
	d.Check(makeFlow(ext, "192.168.1.2", 80, ""))
	det := d.Check(makeFlow(ext, "192.168.1.3", 443, ""))
	if det != nil {
		t.Fatal("brute_force on different ports should not merge counts")
	}
}

func TestBruteForcePruneNoPanic(t *testing.T) {
	d := detector.NewBruteForce(3, 10*time.Second)
	d.Check(makeFlow("1.2.3.4", "192.168.1.1", 22, ""))
	d.Prune()
}
