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
	"github.com/ecan0/serpent-wrt/internal/feed"
	"github.com/ecan0/serpent-wrt/internal/runtime"
)

type fakeEngine struct {
	status     runtime.Status
	stats      runtime.Stats
	reloadErr  error
	recent     []runtime.DetectionRecord
	blocked    []string
	blockedErr error
	feedSnap   feed.Snapshot
	feedResult feed.UpdateResult
	feedErr    error
}

func (f *fakeEngine) GetStatus() runtime.Status {
	return f.status
}

func (f *fakeEngine) GetStats() runtime.Stats {
	return f.stats
}

func (f *fakeEngine) ReloadFeed() error {
	return f.reloadErr
}

func (f *fakeEngine) RecentDetections() []runtime.DetectionRecord {
	return f.recent
}

func (f *fakeEngine) GetBlocked() ([]string, error) {
	return f.blocked, f.blockedErr
}

func (f *fakeEngine) ListFeedEntries() (feed.Snapshot, error) {
	return f.feedSnap, f.feedErr
}

func (f *fakeEngine) ValidateFeedEntries(entries []string) (feed.Snapshot, error) {
	if f.feedErr != nil {
		return feed.Snapshot{}, f.feedErr
	}
	return feed.ValidateEntries(entries)
}

func (f *fakeEngine) AddFeedEntry(_ string) (feed.UpdateResult, error) {
	return f.feedResult, f.feedErr
}

func (f *fakeEngine) RemoveFeedEntry(_ string) (feed.UpdateResult, error) {
	return f.feedResult, f.feedErr
}

func (f *fakeEngine) ReplaceFeedEntries(_ []string) (feed.UpdateResult, error) {
	return f.feedResult, f.feedErr
}

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		ThreatFeedPath: "../../testdata/threat-feed.txt",
		Profile:        "home",
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
	if _, ok := body["suppressed_detections"]; !ok {
		t.Error("response missing suppressed_detections field")
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
	if body.Enforcement.Nft.Checked {
		t.Error("nft check should be skipped when enforcement is disabled")
	}
	if body.Enforcement.Nft.CheckState != "disabled" {
		t.Errorf("nft check_state: got %q, want disabled", body.Enforcement.Nft.CheckState)
	}
	if body.Runtime.Version == "" || body.Runtime.Commit == "" || body.Runtime.BuildDate == "" {
		t.Fatalf("runtime build metadata missing: %+v", body.Runtime)
	}
	if body.Runtime.Profile != "home" {
		t.Errorf("runtime profile: got %q, want home", body.Runtime.Profile)
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

func TestHandleRecentDetectionsSchema(t *testing.T) {
	s := newServer("127.0.0.1:0", &fakeEngine{
		recent: []runtime.DetectionRecord{
			{
				Time:       time.Unix(1, 0).UTC(),
				Detector:   "feed_match",
				Severity:   "high",
				Confidence: 95,
				Reason:     "threat_feed_destination",
				SrcIP:      "192.168.1.10",
				DstIP:      "1.2.3.4",
				DstPort:    443,
				Message:    "hit",
			},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/detections/recent", nil)
	w := httptest.NewRecorder()
	s.handleRecentDetections(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
	var body []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body) != 1 {
		t.Fatalf("recent detections: got %d, want 1", len(body))
	}
	got := body[0]
	wantKeys := map[string]bool{
		"time":       true,
		"detector":   true,
		"severity":   true,
		"confidence": true,
		"reason":     true,
		"src_ip":     true,
		"dst_ip":     true,
		"dst_port":   true,
		"message":    true,
	}
	if len(got) != len(wantKeys) {
		t.Fatalf("schema fields: got %d (%v), want %d", len(got), got, len(wantKeys))
	}
	for key := range wantKeys {
		if _, ok := got[key]; !ok {
			t.Fatalf("schema missing field %q in %v", key, got)
		}
	}
	if got["detector"] != "feed_match" || got["severity"] != "high" || got["confidence"] != float64(95) || got["reason"] != "threat_feed_destination" {
		t.Fatalf("metadata fields changed: %v", got)
	}
	if got["src_ip"] != "192.168.1.10" || got["dst_ip"] != "1.2.3.4" || got["dst_port"] != float64(443) {
		t.Fatalf("flow fields changed: %v", got)
	}
}

func TestHandleFeedGet(t *testing.T) {
	s := newServer("127.0.0.1:0", &fakeEngine{
		feedSnap: feed.Snapshot{
			Path:       "/etc/serpent-wrt/threat-feed.txt",
			Count:      1,
			MaxEntries: feed.MaxManagedEntries,
			Entries:    []feed.Entry{{Value: "1.2.3.4", Type: "ip"}},
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/feed", nil)
	w := httptest.NewRecorder()
	s.handleFeed(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var body feed.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Count != 1 || body.Entries[0].Value != "1.2.3.4" {
		t.Fatalf("body: %+v", body)
	}
}

func TestHandleFeedValidate(t *testing.T) {
	s := newServer("127.0.0.1:0", &fakeEngine{})
	req := httptest.NewRequest(http.MethodPost, "/feed/validate", strings.NewReader(`{"entries":["1.2.3.4","5.6.7.9/24"]}`))
	w := httptest.NewRecorder()
	s.handleFeedValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 body=%q", w.Code, w.Body.String())
	}
	var body feed.Snapshot
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Count != 2 || body.Entries[1].Value != "5.6.7.0/24" {
		t.Fatalf("body: %+v", body)
	}
}

func TestHandleFeedValidateRejectsBadEntry(t *testing.T) {
	s := newServer("127.0.0.1:0", &fakeEngine{})
	req := httptest.NewRequest(http.MethodPost, "/feed/validate", strings.NewReader(`{"entry":"not-an-ip"}`))
	w := httptest.NewRecorder()
	s.handleFeedValidate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

func TestHandleFeedAdd(t *testing.T) {
	s := newServer("127.0.0.1:0", &fakeEngine{
		feedResult: feed.UpdateResult{Path: "/feed.txt", Count: 2, Changed: true},
	})
	req := httptest.NewRequest(http.MethodPost, "/feed/add", strings.NewReader(`{"entry":"1.2.3.4"}`))
	w := httptest.NewRecorder()
	s.handleFeedAdd(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 body=%q", w.Code, w.Body.String())
	}
	var body feed.UpdateResult
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Changed || body.Count != 2 {
		t.Fatalf("body: %+v", body)
	}
}

func TestHandleFeedRemove(t *testing.T) {
	s := newServer("127.0.0.1:0", &fakeEngine{
		feedResult: feed.UpdateResult{Path: "/feed.txt", Count: 1, Changed: true},
	})
	req := httptest.NewRequest(http.MethodPost, "/feed/remove", strings.NewReader(`{"entry":"1.2.3.4"}`))
	w := httptest.NewRecorder()
	s.handleFeedRemove(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 body=%q", w.Code, w.Body.String())
	}
	var body feed.UpdateResult
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Changed || body.Count != 1 {
		t.Fatalf("body: %+v", body)
	}
}

func TestHandleFeedReplace(t *testing.T) {
	s := newServer("127.0.0.1:0", &fakeEngine{
		feedResult: feed.UpdateResult{Path: "/feed.txt", Count: 2, Changed: true},
	})
	req := httptest.NewRequest(http.MethodPut, "/feed", strings.NewReader(`{"entries":["1.2.3.4","5.6.7.0/24"]}`))
	w := httptest.NewRecorder()
	s.handleFeed(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 body=%q", w.Code, w.Body.String())
	}
	var body feed.UpdateResult
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Changed || body.Count != 2 {
		t.Fatalf("body: %+v", body)
	}
}
