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
