package events

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
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

func TestLoggerHonorsMinimumLevel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		level Level
		want  []string
	}{
		{name: "info", level: LevelInfo, want: []string{"info", "warn", "error"}},
		{name: "warn", level: LevelWarn, want: []string{"warn", "error"}},
		{name: "error", level: LevelError, want: []string{"error"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			remote, err := NewUDPSyslog("udp", listener.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer remote.conn.Close()
			logger := newLogger(&output, remote, tc.level)
			for _, event := range []Event{
				{Level: LevelInfo, Type: TypeSystem, Message: "info"},
				{Level: LevelWarn, Type: TypeDetection, Message: "warn"},
				{Level: LevelError, Type: TypeSystem, Message: "error"},
			} {
				logger.Log(event)
			}
			var got []string
			decoder := json.NewDecoder(&output)
			for {
				var event Event
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					t.Fatalf("decode event: %v", err)
				}
				got = append(got, event.Message)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("messages: got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("message[%d]: got %q, want %q", i, got[i], tc.want[i])
				}
			}
			if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 4096)
			for _, want := range tc.want {
				n, _, err := listener.ReadFrom(packet)
				if err != nil {
					t.Fatal(err)
				}
				start := bytes.IndexByte(packet[:n], '{')
				if start < 0 {
					t.Fatalf("syslog packet has no JSON event: %q", packet[:n])
				}
				var event Event
				if err := json.Unmarshal(packet[start:n], &event); err != nil {
					t.Fatal(err)
				}
				if event.Message != want {
					t.Fatalf("syslog message: got %q, want %q", event.Message, want)
				}
			}
		})
	}
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
	wantKeys := map[string]bool{
		"time":       true,
		"level":      true,
		"type":       true,
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

func TestEventContextFieldsSerialize(t *testing.T) {
	event := Event{
		Level:   LevelWarn,
		Type:    TypeDetection,
		RunID:   "e2e-run",
		CaseID:  "scan-01",
		Message: "detection",
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if got["run_id"] != "e2e-run" || got["case_id"] != "scan-01" {
		t.Fatalf("event context: got %v/%v", got["run_id"], got["case_id"])
	}
}

func TestDetectionEventPreservesTranslatedDestination(t *testing.T) {
	e := Event{
		Level:             LevelWarn,
		Type:              TypeDetection,
		Detector:          "feed_match",
		SrcIP:             "1.2.3.4",
		DstIP:             "192.168.100.200",
		DstPort:           18443,
		TranslatedDstIP:   "198.18.0.10",
		TranslatedDstPort: 18180,
		Message:           "translated source-feed hit",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if got["dst_ip"] != "192.168.100.200" || got["dst_port"] != float64(18443) {
		t.Fatalf("original destination fields: %v", got)
	}
	if got["translated_dst_ip"] != "198.18.0.10" || got["translated_dst_port"] != float64(18180) {
		t.Fatalf("translated destination fields: %v", got)
	}
}

func TestDetectionEventPreservesScanPortEvidence(t *testing.T) {
	e := Event{
		Level:             LevelWarn,
		Type:              TypeDetection,
		Detector:          "port_scan",
		DistinctPortCount: 3,
		ObservedDstPorts:  []uint16{22, 80, 443},
		Message:           "scan episode",
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	ports, ok := got["observed_dst_ports"].([]any)
	if !ok || len(ports) != 3 || ports[0] != float64(22) || ports[2] != float64(443) {
		t.Fatalf("observed ports: got %#v", got["observed_dst_ports"])
	}
	if got["distinct_port_count"] != float64(3) {
		t.Fatalf("distinct port count: got %#v", got["distinct_port_count"])
	}
}

func TestDetectionEventLeaseFieldsJSON(t *testing.T) {
	e := Event{
		Level:       LevelWarn,
		Type:        TypeDetection,
		Detector:    "feed_match",
		SrcIP:       "192.168.1.10",
		SrcHostname: "laptop",
		SrcMAC:      "aa:bb:cc:dd:ee:ff",
		DstIP:       "192.168.1.11",
		DstHostname: "server",
		DstMAC:      "11:22:33:44:55:66",
		Message:     "hit",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if got["src_hostname"] != "laptop" || got["src_mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("src lease fields missing: %v", got)
	}
	if got["dst_hostname"] != "server" || got["dst_mac"] != "11:22:33:44:55:66" {
		t.Fatalf("dst lease fields missing: %v", got)
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
