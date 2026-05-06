package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/events"
	"github.com/ecan0/serpent-wrt/internal/runtime"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		ThreatFeedPath: "../../testdata/threat-feed.txt",
		PollInterval:   5 * time.Second,
		BlockDuration:  time.Hour,
		DedupWindow:    5 * time.Minute,
		NftTable:       "serpent_wrt",
		NftSet:         "blocked_ips",
		APIEnabled:     true,
		APIBind:        "127.0.0.1:0",
		Detectors: config.DetectorsConfig{
			Fanout:     config.FanoutConfig{DistinctDstThreshold: 50, Window: 60 * time.Second},
			Scan:       config.ScanConfig{DistinctPortThreshold: 30, Window: 60 * time.Second},
			Beacon:     config.BeaconConfig{MinHits: 5, Tolerance: 3 * time.Second, Window: 5 * time.Minute, MinInterval: 5 * time.Second},
			ExtScan:    config.ExtScanConfig{DistinctPortThreshold: 20, Window: 60 * time.Second},
			BruteForce: config.BruteForceConfig{Threshold: 5, Window: 60 * time.Second},
		},
	}
	eng := runtime.NewEngine(cfg, events.NewLogger(nil))
	return New(cfg.APIBind, eng)
}

func TestHandleHealthz(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field: got %q, want ok", body["status"])
	}
}

func TestHandleStats(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	s.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := body["flows_seen"]; !ok {
		t.Error("response missing flows_seen field")
	}
}

func TestHandleStatus(t *testing.T) {
	s := testServer(t)
	if err := s.eng.ReloadFeed(); err != nil {
		t.Fatalf("reload feed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
	var body runtime.Status
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status field: got %q, want ok", body.Status)
	}
	if body.Feed.Count == 0 {
		t.Error("feed count should be populated after reload")
	}
	if body.StartedAt.IsZero() {
		t.Error("started_at should not be zero")
	}
	if body.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds: got %d, want non-negative", body.UptimeSeconds)
	}
	if body.Enforcement.Enabled {
		t.Error("test config should report enforcement disabled")
	}
	if body.Enforcement.Nft.SetupState != "disabled" {
		t.Errorf("nft setup_state: got %q, want disabled", body.Enforcement.Nft.SetupState)
	}
	if body.Runtime.Version == "" || body.Runtime.Commit == "" || body.Runtime.BuildDate == "" {
		t.Fatalf("runtime build metadata missing: %+v", body.Runtime)
	}
	if body.Detectors.Fanout.DistinctDstThreshold != 50 {
		t.Errorf("fanout threshold: got %d, want 50", body.Detectors.Fanout.DistinctDstThreshold)
	}
}

func TestHandleReloadMethodNotAllowed(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/reload", nil)
	w := httptest.NewRecorder()
	s.handleReload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want 405", w.Code)
	}
}

func TestHandleReloadPost(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/reload", strings.NewReader(""))
	w := httptest.NewRecorder()
	s.handleReload(w, req)

	// testdata/threat-feed.txt exists, so reload should succeed.
	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "reloaded" {
		t.Errorf("status field: got %q, want reloaded", body["status"])
	}
}

func TestHandleRecentDetections(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/detections/recent", nil)
	w := httptest.NewRecorder()
	s.handleRecentDetections(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	// Response must be a JSON array (empty on fresh engine).
	var body []any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response (expected array): %v", err)
	}
}
