package events

import (
	"encoding/json"
	"net"
	"testing"
)

func TestIPStrNil(t *testing.T) {
	if s := ipStr(nil); s != "" {
		t.Errorf("ipStr(nil): got %q, want empty string", s)
	}
}

func TestIPStrValid(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	if s := ipStr(ip); s != "1.2.3.4" {
		t.Errorf("ipStr: got %q, want 1.2.3.4", s)
	}
}

func TestLevelConstants(t *testing.T) {
	if LevelInfo != "info" {
		t.Errorf("LevelInfo: got %q, want info", LevelInfo)
	}
	if LevelWarn != "warn" {
		t.Errorf("LevelWarn: got %q, want warn", LevelWarn)
	}
	if LevelError != "error" {
		t.Errorf("LevelError: got %q, want error", LevelError)
	}
}

func TestEventTypeConstants(t *testing.T) {
	if TypeDetection != "detection" {
		t.Errorf("TypeDetection: got %q", TypeDetection)
	}
	if TypeEnforcement != "enforcement" {
		t.Errorf("TypeEnforcement: got %q", TypeEnforcement)
	}
	if TypeSystem != "system" {
		t.Errorf("TypeSystem: got %q", TypeSystem)
	}
}

func TestLoggerNilRemote(t *testing.T) {
	log := NewLogger(nil)
	// None of these should panic.
	log.Info("startup message")
	log.Error("something went wrong")
	log.Detection("feed_match", "hit", net.ParseIP("192.168.1.1"), net.ParseIP("1.2.3.4"), 443)
	log.Enforcement("blocked 1.2.3.4", net.ParseIP("1.2.3.4"))
}

func TestLoggerNilIPs(t *testing.T) {
	log := NewLogger(nil)
	// nil IPs in Detection and Enforcement must not panic.
	log.Detection("fanout", "msg", nil, nil, 0)
	log.Enforcement("msg", nil)
}

func TestLogSetTimestamp(t *testing.T) {
	log := NewLogger(nil)
	// Event with zero time must not panic; logger fills it in.
	log.Log(Event{Level: LevelInfo, Type: TypeSystem, Message: "test"})
}

func TestLogAllLevels(t *testing.T) {
	log := NewLogger(nil)
	log.Log(Event{Level: LevelInfo, Type: TypeSystem, Message: "info"})
	log.Log(Event{Level: LevelWarn, Type: TypeDetection, Message: "warn"})
	log.Log(Event{Level: LevelError, Type: TypeSystem, Message: "error"})
}

func TestDetectionEventMetadataJSON(t *testing.T) {
	e := Event{
		Level:      LevelWarn,
		Type:       TypeDetection,
		Detector:   "feed_match",
		Severity:   "high",
		Confidence: 95,
		Reason:     "threat_feed_destination",
		SrcIP:      "192.168.1.10",
		DstIP:      "1.2.3.4",
		DstPort:    443,
		Message:    "hit",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if got["severity"] != "high" {
		t.Fatalf("severity: got %v, want high", got["severity"])
	}
	if got["confidence"] != float64(95) {
		t.Fatalf("confidence: got %v, want 95", got["confidence"])
	}
	if got["reason"] != "threat_feed_destination" {
		t.Fatalf("reason: got %v, want threat_feed_destination", got["reason"])
	}
}

func TestSystemEventFieldsJSON(t *testing.T) {
	feedCount := 42
	e := Event{
		Level:     LevelError,
		Type:      TypeSystem,
		Component: "feed",
		Action:    "reload",
		Status:    "failure",
		Error:     "open feed: missing",
		FeedCount: &feedCount,
		Addr:      "127.0.0.1:8080",
		Message:   "reload threat feed failed",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if got["component"] != "feed" {
		t.Fatalf("component: got %v, want feed", got["component"])
	}
	if got["action"] != "reload" {
		t.Fatalf("action: got %v, want reload", got["action"])
	}
	if got["status"] != "failure" {
		t.Fatalf("status: got %v, want failure", got["status"])
	}
	if got["error"] != "open feed: missing" {
		t.Fatalf("error: got %v, want open feed: missing", got["error"])
	}
	if got["feed_count"] != float64(42) {
		t.Fatalf("feed_count: got %v, want 42", got["feed_count"])
	}
	if got["addr"] != "127.0.0.1:8080" {
		t.Fatalf("addr: got %v, want 127.0.0.1:8080", got["addr"])
	}
}
