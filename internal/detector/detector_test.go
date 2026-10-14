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

func assertDetectionMeta(t *testing.T, det *detector.Detection, severity detector.Severity, reason detector.Reason) {
	t.Helper()
	if det.Severity != severity {
		t.Fatalf("severity: got %q, want %q", det.Severity, severity)
	}
	if det.Reason != reason {
		t.Fatalf("reason: got %q, want %q", det.Reason, reason)
	}
	if det.Confidence == 0 || det.Confidence > 100 {
		t.Fatalf("confidence: got %d, want 1..100", det.Confidence)
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
		return
	}
	if det.Type != "feed_match" {
		t.Errorf("type: got %q, want feed_match", det.Type)
	}
	assertDetectionMeta(t, det, detector.SeverityHigh, detector.ReasonThreatFeedDestination)
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

func TestFeedMatchTranslatedDestination(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load feed: %v", err)
	}
	d := detector.NewFeedMatch(f)
	r := makeFlow("192.168.1.10", "192.0.2.50", 18443, "SYN_SENT")
	r.ReplySrcIP = net.ParseIP("1.2.3.4")
	r.ReplySrcPort = 18180

	det := d.Check(r)
	if det == nil {
		t.Fatal("expected feed match for translated destination 1.2.3.4")
		return
	}
	assertDetectionMeta(t, det, detector.SeverityHigh, detector.ReasonThreatFeedDestination)
	if det.DstIP.String() != "192.0.2.50" || det.DstPort != 18443 {
		t.Fatalf("original destination: got %s:%d", det.DstIP, det.DstPort)
	}
	if det.TranslatedDstIP.String() != "1.2.3.4" || det.TranslatedDstPort != 18180 {
		t.Fatalf("translated destination: got %s:%d", det.TranslatedDstIP, det.TranslatedDstPort)
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
		return
	}
	if det.Type != "fanout" {
		t.Errorf("type: got %q, want fanout", det.Type)
	}
	assertDetectionMeta(t, det, detector.SeverityMedium, detector.ReasonOutboundDistinctDestinations)
	if det.Confidence != 70 {
		t.Errorf("confidence at threshold: got %d, want 70", det.Confidence)
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
		return
	}
	if det.Type != "port_scan" {
		t.Errorf("type: got %q, want port_scan", det.Type)
	}
	assertDetectionMeta(t, det, detector.SeverityMedium, detector.ReasonOutboundDistinctPorts)
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

func TestPortScanEmitsOneEvidenceRecordPerWindowEpisode(t *testing.T) {
	d := detector.NewPortScan(3, 25*time.Millisecond)
	src, dst := "192.168.1.2", "10.0.0.2"
	var first *detector.Detection
	for _, port := range []uint16{22, 80, 443} {
		first = d.Check(makeFlow(src, dst, port, ""))
	}
	if first == nil || first.DistinctPortCount != 3 {
		t.Fatalf("threshold alert: got %+v, want three distinct ports", first)
	}
	if got := first.ObservedDstPorts; len(got) != 3 || got[0] != 22 || got[1] != 80 || got[2] != 443 {
		t.Fatalf("threshold port evidence: got %v, want [22 80 443]", got)
	}
	for _, port := range []uint16{8080, 8443} {
		if det := d.Check(makeFlow(src, dst, port, "")); det != nil {
			t.Fatalf("same scan episode emitted another alert: %+v", det)
		}
	}

	time.Sleep(35 * time.Millisecond)
	for _, port := range []uint16{53, 80, 443} {
		first = d.Check(makeFlow(src, dst, port, ""))
	}
	if first == nil || first.DistinctPortCount != 3 {
		t.Fatalf("new episode after window expiry: got %+v", first)
	}
	if got := first.ObservedDstPorts; len(got) != 3 || got[0] != 53 || got[1] != 80 || got[2] != 443 {
		t.Fatalf("new episode port evidence: got %v, want [53 80 443]", got)
	}
}

func TestExtScanEmitsOneEvidenceRecordPerWindowEpisode(t *testing.T) {
	d := detector.NewExtScan(3, 25*time.Millisecond)
	src, dst := "203.0.113.10", "192.168.1.10"
	var first *detector.Detection
	for _, port := range []uint16{22, 80, 443} {
		first = d.Check(makeFlow(src, dst, port, ""))
	}
	if first == nil || first.DistinctPortCount != 3 {
		t.Fatalf("threshold alert: got %+v, want three distinct ports", first)
	}
	if got := first.ObservedDstPorts; len(got) != 3 || got[0] != 22 || got[1] != 80 || got[2] != 443 {
		t.Fatalf("threshold port evidence: got %v, want [22 80 443]", got)
	}
	for _, port := range []uint16{8080, 8443} {
		if det := d.Check(makeFlow(src, dst, port, "")); det != nil {
			t.Fatalf("same scan episode emitted another alert: %+v", det)
		}
	}

	time.Sleep(35 * time.Millisecond)
	for _, port := range []uint16{53, 80, 443} {
		first = d.Check(makeFlow(src, dst, port, ""))
	}
	if first == nil || first.DistinctPortCount != 3 {
		t.Fatalf("new episode after window expiry: got %+v", first)
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
		return
	}
	if det.Type != "feed_match" {
		t.Errorf("type: got %q, want feed_match", det.Type)
	}
	assertDetectionMeta(t, det, detector.SeverityHigh, detector.ReasonThreatFeedSource)
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
		return
	}
	if det.Type != "ext_scan" {
		t.Errorf("type: got %q, want ext_scan", det.Type)
	}
	assertDetectionMeta(t, det, detector.SeverityMedium, detector.ReasonInboundDistinctPorts)
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
		return
	}
	if det.Type != "brute_force" {
		t.Errorf("type: got %q, want brute_force", det.Type)
	}
	assertDetectionMeta(t, det, detector.SeverityHigh, detector.ReasonInboundServiceSpray)
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
