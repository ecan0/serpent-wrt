package runtime

import (
	"net"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
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
		Detectors: config.DetectorsConfig{
			Fanout: config.FanoutConfig{DistinctDstThreshold: 50, Window: 60 * time.Second},
			Scan:   config.ScanConfig{DistinctPortThreshold: 30, Window: 60 * time.Second},
			Beacon: config.BeaconConfig{MinHits: 5, Tolerance: 3 * time.Second, Window: 5 * time.Minute},
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
