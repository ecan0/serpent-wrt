package runtime

import (
	"net"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/detector"
	"github.com/ecan0/serpent-wrt/internal/events"
)

func testConfig() *config.Config {
	return &config.Config{
		ThreatFeedPath: "../../testdata/threat-feed.txt",
		PollInterval:   5 * time.Second,
		BlockDuration:  time.Hour,
		NftTable:       "serpent_wrt",
		NftSet:         "blocked_ips",
		LANCIDRs:       []string{"192.168.1.0/24", "10.0.0.0/8"},
		SelfIPs:        []string{"192.168.1.1"},
		Detectors: config.DetectorsConfig{
			Fanout:     config.FanoutConfig{DistinctDstThreshold: 50, Window: 60 * time.Second},
			Scan:       config.ScanConfig{DistinctPortThreshold: 30, Window: 60 * time.Second},
			Beacon:     config.BeaconConfig{MinHits: 5, Tolerance: 3 * time.Second, Window: 5 * time.Minute},
			ExtScan:    config.ExtScanConfig{DistinctPortThreshold: 20, Window: 60 * time.Second},
			BruteForce: config.BruteForceConfig{Threshold: 5, Window: 60 * time.Second},
		},
	}
}

func testEngine(t *testing.T) *Engine {
	t.Helper()
	return NewEngine(testConfig(), events.NewLogger(nil))
}

// --- isLAN ---

func TestIsLANInSubnet(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.254", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"172.16.0.1", false}, // not in configured CIDRs
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		got := e.isLAN(ip)
		if got != tc.want {
			t.Errorf("isLAN(%s): got %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsLANNil(t *testing.T) {
	e := testEngine(t)
	// nil IP is treated conservatively as LAN (skip it).
	if !e.isLAN(nil) {
		t.Error("isLAN(nil) should return true")
	}
}

// --- NewEngine ---

func TestNewEngine(t *testing.T) {
	e := testEngine(t)
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if e.cfg == nil {
		t.Error("engine cfg is nil")
	}
	if e.log == nil {
		t.Error("engine log is nil")
	}
	if len(e.lanNets) != 2 {
		t.Errorf("lanNets: got %d, want 2", len(e.lanNets))
	}
	if len(e.selfIPs) != 1 {
		t.Errorf("selfIPs: got %d, want 1", len(e.selfIPs))
	}
}

// --- isUnroutable ---

func TestIsUnroutable(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		got := isUnroutable(ip)
		if got != tc.want {
			t.Errorf("isUnroutable(%s): got %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsUnroutableNil(t *testing.T) {
	if !isUnroutable(nil) {
		t.Error("isUnroutable(nil) should return true")
	}
}

// --- isSelf ---

func TestIsSelf(t *testing.T) {
	e := testEngine(t)
	if !e.isSelf(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 is in self_ips, should return true")
	}
	if e.isSelf(net.ParseIP("192.168.1.2")) {
		t.Error("192.168.1.2 is not in self_ips")
	}
	if e.isSelf(nil) {
		t.Error("isSelf(nil) should return false")
	}
}

// --- GetStats ---

func TestGetStatsInitial(t *testing.T) {
	e := testEngine(t)
	s := e.GetStats()
	if s.FlowsSeen != 0 {
		t.Errorf("FlowsSeen: got %d, want 0", s.FlowsSeen)
	}
	if s.BlocksApplied != 0 {
		t.Errorf("BlocksApplied: got %d, want 0", s.BlocksApplied)
	}
	if s.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
	if s.DetectionsByType == nil {
		t.Error("DetectionsByType should not be nil")
	}
}

// --- RecentDetections ---

func TestRecentDetectionsEmpty(t *testing.T) {
	e := testEngine(t)
	dets := e.RecentDetections()
	if len(dets) != 0 {
		t.Errorf("RecentDetections: got %d entries, want 0", len(dets))
	}
}

func TestRecentDetectionsRingBuffer(t *testing.T) {
	e := testEngine(t)

	// Manually fill a few entries into the ring buffer.
	now := time.Now()
	for i := 0; i < 3; i++ {
		e.recentMu.Lock()
		e.recent[e.rHead] = DetectionRecord{
			Time:     now,
			Detector: "feed_match",
			SrcIP:    "192.168.1.1",
			Message:  "test",
		}
		e.rHead = (e.rHead + 1) % recentCap
		e.recentMu.Unlock()
	}

	dets := e.RecentDetections()
	if len(dets) != 3 {
		t.Errorf("RecentDetections: got %d, want 3", len(dets))
	}
}

// --- ReloadFeed ---

// --- Configurable dedup window ---

func TestDedupWindowFromConfig(t *testing.T) {
	cfg := testConfig()
	cfg.DedupWindow = 30 * time.Second
	e := NewEngine(cfg, events.NewLogger(nil))
	if e.dedupWindow != 30*time.Second {
		t.Errorf("dedupWindow: got %v, want 30s", e.dedupWindow)
	}
}

func TestDedupWindowDefault(t *testing.T) {
	e := testEngine(t)
	// testConfig leaves DedupWindow zero; NewEngine receives the zero value.
	// applyDefaults (called at Load time) would set 5m, but testConfig bypasses Load.
	// Engine should still have whatever the config provides, so verify the field is set.
	if e.dedupWindow != 0 {
		t.Errorf("dedupWindow: got %v, want 0 (testConfig bypasses applyDefaults)", e.dedupWindow)
	}
}

func TestDedupWindowSuppression(t *testing.T) {
	cfg := testConfig()
	cfg.DedupWindow = 50 * time.Millisecond
	e := NewEngine(cfg, events.NewLogger(nil))

	det := &detector.Detection{
		Type:    "feed_match",
		SrcIP:   net.ParseIP("192.168.1.10"),
		DstIP:   net.ParseIP("8.8.8.8"),
		Message: "test",
	}

	// First detection should pass through.
	e.handleDetection(det)
	s1 := e.GetStats()
	if s1.DetectionsByType["feed_match"] != 1 {
		t.Fatalf("first detection not counted: got %d", s1.DetectionsByType["feed_match"])
	}

	// Immediate duplicate should be suppressed.
	e.handleDetection(det)
	s2 := e.GetStats()
	if s2.DetectionsByType["feed_match"] != 1 {
		t.Fatalf("duplicate not suppressed: got %d", s2.DetectionsByType["feed_match"])
	}

	// After window expires, should fire again.
	time.Sleep(60 * time.Millisecond)
	e.handleDetection(det)
	s3 := e.GetStats()
	if s3.DetectionsByType["feed_match"] != 2 {
		t.Fatalf("post-window detection not counted: got %d", s3.DetectionsByType["feed_match"])
	}
}

// --- ReloadFeed ---

func TestReloadFeedMissingFile(t *testing.T) {
	cfg := testConfig()
	cfg.ThreatFeedPath = "/nonexistent/path/feed.txt"
	e := NewEngine(cfg, events.NewLogger(nil))
	if err := e.ReloadFeed(); err == nil {
		t.Fatal("expected error reloading nonexistent feed file")
	}
}

func TestReloadFeedSuccess(t *testing.T) {
	e := testEngine(t)
	// testdata/threat-feed.txt exists; reload should succeed.
	if err := e.ReloadFeed(); err != nil {
		t.Errorf("ReloadFeed: unexpected error: %v", err)
	}
}
