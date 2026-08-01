package collector

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseLineTCPEstablished(t *testing.T) {
	line := "ipv4 2 tcp 6 3599 ESTABLISHED src=192.168.1.1 dst=8.8.8.8 sport=45678 dport=443 src=8.8.8.8 dst=192.168.1.1 sport=443 dport=45678 [ASSURED]"
	r, ok := parseLine(line, time.Now())
	if !ok {
		t.Fatal("expected ok=true for TCP ESTABLISHED line")
	}
	if r.Proto != "tcp" {
		t.Errorf("proto: got %q, want tcp", r.Proto)
	}
	if r.SrcIP.String() != "192.168.1.1" {
		t.Errorf("src_ip: got %s, want 192.168.1.1", r.SrcIP)
	}
	if r.DstIP.String() != "8.8.8.8" {
		t.Errorf("dst_ip: got %s, want 8.8.8.8", r.DstIP)
	}
	if r.SrcPort != 45678 {
		t.Errorf("src_port: got %d, want 45678", r.SrcPort)
	}
	if r.DstPort != 443 {
		t.Errorf("dst_port: got %d, want 443", r.DstPort)
	}
	if r.State != "ESTABLISHED" {
		t.Errorf("state: got %q, want ESTABLISHED", r.State)
	}
}

func TestParseLineConntrackNewEvent(t *testing.T) {
	line := "[NEW] tcp 6 120 SYN_SENT src=192.168.1.10 dst=8.8.8.8 sport=45678 dport=443"
	r, ok := parseLine(line, time.Now())
	if !ok {
		t.Fatal("expected conntrack NEW event to parse")
	}
	if r.Proto != "tcp" || r.State != "SYN_SENT" {
		t.Fatalf("protocol/state: got %s/%s, want tcp/SYN_SENT", r.Proto, r.State)
	}
	if r.SrcIP.String() != "192.168.1.10" || r.DstIP.String() != "8.8.8.8" {
		t.Fatalf("tuple: got %s -> %s", r.SrcIP, r.DstIP)
	}
	if r.SrcPort != 45678 || r.DstPort != 443 {
		t.Fatalf("ports: got %d -> %d", r.SrcPort, r.DstPort)
	}
}

func TestParseLineTCPSynSent(t *testing.T) {
	line := "ipv4 2 tcp 6 60 SYN_SENT src=10.0.0.1 dst=1.2.3.4 sport=54321 dport=80 [UNREPLIED]"
	r, ok := parseLine(line, time.Now())
	if !ok {
		t.Fatal("expected ok=true for TCP SYN_SENT line")
	}
	if r.State != "SYN_SENT" {
		t.Errorf("state: got %q, want SYN_SENT", r.State)
	}
	if r.DstPort != 80 {
		t.Errorf("dst_port: got %d, want 80", r.DstPort)
	}
}

func TestParseLineUDP(t *testing.T) {
	line := "ipv4 2 udp 17 30 src=10.0.0.1 dst=1.1.1.1 sport=12345 dport=53 src=1.1.1.1 dst=10.0.0.1 sport=53 dport=12345 [UNREPLIED]"
	r, ok := parseLine(line, time.Now())
	if !ok {
		t.Fatal("expected ok=true for UDP line")
	}
	if r.Proto != "udp" {
		t.Errorf("proto: got %q, want udp", r.Proto)
	}
	if r.State != "" {
		t.Errorf("state: got %q, want empty for UDP", r.State)
	}
	if r.DstPort != 53 {
		t.Errorf("dst_port: got %d, want 53", r.DstPort)
	}
}

func TestParseLineIPv6(t *testing.T) {
	line := "ipv6 10 tcp 6 3599 ESTABLISHED src=2001:db8::1 dst=2001:db8::2 sport=12345 dport=443 src=2001:db8::2 dst=2001:db8::1 sport=443 dport=12345"
	r, ok := parseLine(line, time.Now())
	if !ok {
		t.Fatal("expected IPv6 line to parse")
	}
	if r.SrcIP.String() != "2001:db8::1" || r.DstIP.String() != "2001:db8::2" {
		t.Fatalf("tuple: got %s -> %s", r.SrcIP, r.DstIP)
	}
}

func TestParseLineEmpty(t *testing.T) {
	_, ok := parseLine("", time.Now())
	if ok {
		t.Fatal("expected empty line to return false")
	}
}

func TestParseLineWhitespace(t *testing.T) {
	_, ok := parseLine("   ", time.Now())
	if ok {
		t.Fatal("expected whitespace-only line to return false")
	}
}

func TestParseLineTooFewFields(t *testing.T) {
	_, ok := parseLine("ipv4 2 tcp 6", time.Now())
	if ok {
		t.Fatal("expected too-few-fields line to return false")
	}
}

func TestParseLineNonTCPUDP(t *testing.T) {
	line := "ipv4 2 icmp 1 30 src=1.1.1.1 dst=2.2.2.2 type=8 code=0"
	_, ok := parseLine(line, time.Now())
	if ok {
		t.Fatal("expected non-tcp/udp proto to return false")
	}
}

func TestParseLineMissingIPs(t *testing.T) {
	line := "ipv4 2 tcp 6 3599 ESTABLISHED sport=80 dport=443"
	_, ok := parseLine(line, time.Now())
	if ok {
		t.Fatal("expected line missing src/dst IPs to return false")
	}
}

// Forward-direction tuple must be the first occurrence of src/dst/sport/dport.
// The reply direction repeats them in reverse; bitmask should capture only the first.
func TestParseLineForwardTupleOnly(t *testing.T) {
	line := "ipv4 2 tcp 6 3599 ESTABLISHED src=192.168.1.5 dst=8.8.4.4 sport=11111 dport=80 src=8.8.4.4 dst=192.168.1.5 sport=80 dport=11111 [ASSURED]"
	r, ok := parseLine(line, time.Now())
	if !ok {
		t.Fatal("expected ok")
	}
	if r.SrcIP.String() != "192.168.1.5" {
		t.Errorf("src_ip: got %s, want 192.168.1.5 (forward direction)", r.SrcIP)
	}
	if r.DstIP.String() != "8.8.4.4" {
		t.Errorf("dst_ip: got %s, want 8.8.4.4 (forward direction)", r.DstIP)
	}
	if r.SrcPort != 11111 {
		t.Errorf("src_port: got %d, want 11111 (forward direction)", r.SrcPort)
	}
	if r.DstPort != 80 {
		t.Errorf("dst_port: got %d, want 80 (forward direction)", r.DstPort)
	}
}

func TestParseMultipleLines(t *testing.T) {
	input := strings.Join([]string{
		"ipv4 2 tcp 6 3599 ESTABLISHED src=192.168.1.1 dst=8.8.8.8 sport=1001 dport=443 src=8.8.8.8 dst=192.168.1.1 sport=443 dport=1001",
		"ipv4 2 udp 17 30 src=10.0.0.1 dst=1.1.1.1 sport=5000 dport=53 src=1.1.1.1 dst=10.0.0.1 sport=53 dport=5000",
		"ipv6 10 tcp 6 100 ESTABLISHED src=::1 dst=::2 sport=1234 dport=80",
		"",
	}, "\n")
	records, err := parse(bufio.NewScanner(strings.NewReader(input)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("got %d records, want 3 (including IPv6)", len(records))
	}
}

func TestStartEventsStreamsNewRecords(t *testing.T) {
	command := filepath.Join(t.TempDir(), "fake-conntrack")
	script := "#!/bin/sh\nprintf '%s\\n' '[NEW] udp 17 30 src=192.168.1.2 dst=1.1.1.1 sport=53000 dport=53'\n"
	if err := os.WriteFile(command, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	stream, err := startEvents(context.Background(), command)
	if err != nil {
		t.Fatalf("start events: %v", err)
	}
	record, ok := <-stream.Records
	if !ok {
		t.Fatal("event stream closed before yielding a record")
	}
	if record.Proto != "udp" || record.DstIP.String() != "1.1.1.1" || record.DstPort != 53 {
		t.Fatalf("record: got %#v", record)
	}
	if err := <-stream.Done; err == nil || !strings.Contains(err.Error(), "event stream ended") {
		t.Fatalf("done: got %v, want clean-end error", err)
	}
}

func TestStartEventsReportsMissingCommand(t *testing.T) {
	command := filepath.Join(t.TempDir(), "missing-conntrack")
	if _, err := startEvents(context.Background(), command); err == nil ||
		!strings.Contains(err.Error(), "start conntrack event stream") {
		t.Fatalf("error: got %v, want command startup failure", err)
	}
}
