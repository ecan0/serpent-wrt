package config_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
)

func TestLoadExample(t *testing.T) {
	cfg, err := config.Load("../../configs/serpent-wrt.example.yaml")
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("poll_interval: got %v, want 5s", cfg.PollInterval)
	}
	if cfg.Profile != "home" {
		t.Errorf("profile: got %q, want home", cfg.Profile)
	}
	if cfg.NftTable != "serpent_wrt" {
		t.Errorf("nft_table: got %q, want serpent_wrt", cfg.NftTable)
	}
	if cfg.NftSet != "blocked_ips" {
		t.Errorf("nft_set: got %q, want blocked_ips", cfg.NftSet)
	}
	if !cfg.APIEnabled {
		t.Error("api_enabled should be true in example config")
	}
}

func TestLoadDefaults(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\n")
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load minimal config: %v", err)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("default poll_interval: got %v", cfg.PollInterval)
	}
	if cfg.NftTable != "serpent_wrt" {
		t.Errorf("default nft_table: got %q", cfg.NftTable)
	}
	if cfg.BlockDuration != time.Hour {
		t.Errorf("default block_duration: got %v", cfg.BlockDuration)
	}
	if cfg.Profile != "home" {
		t.Errorf("default profile: got %q, want home", cfg.Profile)
	}
}

func TestLoadMissingFeedPath(t *testing.T) {
	f := writeTemp(t, "poll_interval: 5s\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for missing threat_feed_path")
	}
}

func TestLoadInvalidCIDR(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./f.txt\nlan_cidrs:\n  - notacidr\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid lan_cidr")
	}
	if !strings.Contains(err.Error(), "lan_cidrs[0]") {
		t.Fatalf("error: got %q, want lan_cidrs[0] context", err)
	}
}

func TestLoadInvalidSelfIP(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./f.txt\nself_ips:\n  - not-an-ip\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid self_ips")
	}
	if !strings.Contains(err.Error(), "self_ips[0]") {
		t.Fatalf("error: got %q, want self_ips[0] context", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadDetectorDefaults(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\n")
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load minimal config: %v", err)
	}
	if cfg.Detectors.Fanout.DistinctDstThreshold != 50 {
		t.Errorf("fanout threshold default: got %d, want 50", cfg.Detectors.Fanout.DistinctDstThreshold)
	}
	if cfg.Detectors.Fanout.Window != 60*time.Second {
		t.Errorf("fanout window default: got %v, want 60s", cfg.Detectors.Fanout.Window)
	}
	if cfg.Detectors.Scan.DistinctPortThreshold != 30 {
		t.Errorf("scan threshold default: got %d, want 30", cfg.Detectors.Scan.DistinctPortThreshold)
	}
	if cfg.Detectors.Scan.Window != 60*time.Second {
		t.Errorf("scan window default: got %v, want 60s", cfg.Detectors.Scan.Window)
	}
	if cfg.Detectors.Beacon.MinHits != 5 {
		t.Errorf("beacon min_hits default: got %d, want 5", cfg.Detectors.Beacon.MinHits)
	}
	if cfg.Detectors.Beacon.Tolerance != 3*time.Second {
		t.Errorf("beacon tolerance default: got %v, want 3s", cfg.Detectors.Beacon.Tolerance)
	}
	if cfg.Detectors.Beacon.Window != 5*time.Minute {
		t.Errorf("beacon window default: got %v, want 5m", cfg.Detectors.Beacon.Window)
	}
}

func TestLoadQuietProfileDefaults(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nprofile: quiet\n")
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load quiet profile: %v", err)
	}
	if cfg.Profile != "quiet" {
		t.Errorf("profile: got %q, want quiet", cfg.Profile)
	}
	if cfg.Detectors.Fanout.DistinctDstThreshold != 100 {
		t.Errorf("fanout threshold: got %d, want 100", cfg.Detectors.Fanout.DistinctDstThreshold)
	}
	if cfg.Detectors.Fanout.Window != 90*time.Second {
		t.Errorf("fanout window: got %v, want 90s", cfg.Detectors.Fanout.Window)
	}
	if cfg.Detectors.Scan.DistinctPortThreshold != 60 {
		t.Errorf("scan threshold: got %d, want 60", cfg.Detectors.Scan.DistinctPortThreshold)
	}
	if cfg.Detectors.Beacon.MinHits != 7 {
		t.Errorf("beacon min_hits: got %d, want 7", cfg.Detectors.Beacon.MinHits)
	}
	if cfg.Detectors.BruteForce.Threshold != 10 {
		t.Errorf("brute_force threshold: got %d, want 10", cfg.Detectors.BruteForce.Threshold)
	}
}

func TestLoadProfileAllowsExplicitDetectorOverrides(t *testing.T) {
	f := writeTemp(t, `threat_feed_path: ./feed.txt
profile: paranoid
detectors:
  fanout:
    distinct_dst_threshold: 99
  beacon:
    window: 12m
`)
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load profile overrides: %v", err)
	}
	if cfg.Detectors.Fanout.DistinctDstThreshold != 99 {
		t.Errorf("fanout threshold: got %d, want explicit 99", cfg.Detectors.Fanout.DistinctDstThreshold)
	}
	if cfg.Detectors.Fanout.Window != 60*time.Second {
		t.Errorf("fanout window: got %v, want paranoid default 60s", cfg.Detectors.Fanout.Window)
	}
	if cfg.Detectors.Beacon.Window != 12*time.Minute {
		t.Errorf("beacon window: got %v, want explicit 12m", cfg.Detectors.Beacon.Window)
	}
	if cfg.Detectors.Beacon.MinHits != 4 {
		t.Errorf("beacon min_hits: got %d, want paranoid default 4", cfg.Detectors.Beacon.MinHits)
	}
}

func TestLoadInvalidProfile(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nprofile: loud\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("error: got %q, want profile context", err)
	}
}

func TestLoadSyslogProtoDefault(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nsyslog_target: \"10.0.0.1:514\"\n")
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load syslog config: %v", err)
	}
	if cfg.SyslogProto != "udp" {
		t.Errorf("syslog_proto default: got %q, want udp", cfg.SyslogProto)
	}
}

func TestLoadSyslogProtoExplicit(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nsyslog_target: \"10.0.0.1:514\"\nsyslog_proto: tcp\n")
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load syslog config: %v", err)
	}
	if cfg.SyslogProto != "tcp" {
		t.Errorf("syslog_proto: got %q, want tcp", cfg.SyslogProto)
	}
}

func TestLoadAPIBindDefault(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\napi_enabled: true\n")
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.APIBind != "127.0.0.1:8080" {
		t.Errorf("api_bind default: got %q, want 127.0.0.1:8080", cfg.APIBind)
	}
}

func TestLoadInvalidAPIBind(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\napi_enabled: true\napi_bind: bad-bind\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid api_bind")
	}
	if !strings.Contains(err.Error(), "api_bind") {
		t.Fatalf("error: got %q, want api_bind context", err)
	}
}

func TestLoadInvalidSyslogTarget(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nsyslog_target: bad-target\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid syslog_target")
	}
	if !strings.Contains(err.Error(), "syslog_target") {
		t.Fatalf("error: got %q, want syslog_target context", err)
	}
}

func TestLoadInvalidSyslogProto(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nsyslog_target: \"10.0.0.1:514\"\nsyslog_proto: quic\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid syslog_proto")
	}
	if !strings.Contains(err.Error(), "syslog_proto") {
		t.Fatalf("error: got %q, want syslog_proto context", err)
	}
}

func TestLoadInvalidNftTable(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nnft_table: \"bad; flush ruleset\"\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid nft_table")
	}
	if !strings.Contains(err.Error(), "nft_table") {
		t.Fatalf("error: got %q, want nft_table context", err)
	}
}

func TestLoadInvalidNftSet(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nnft_set: \"blocked-ips\"\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid nft_set")
	}
	if !strings.Contains(err.Error(), "nft_set") {
		t.Fatalf("error: got %q, want nft_set context", err)
	}
}

func TestLoadSuppressionRules(t *testing.T) {
	f := writeTemp(t, `threat_feed_path: ./feed.txt
suppression_rules:
  - name: trusted scanner
    detectors: [port_scan, ext_scan]
    src_addrs:
      - 192.168.1.50
      - 10.10.0.0/16
    dst_ports: [22, 443]
`)
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.SuppressionRules) != 1 {
		t.Fatalf("suppression_rules: got %d, want 1", len(cfg.SuppressionRules))
	}
	rule := cfg.SuppressionRules[0]
	if rule.Name != "trusted scanner" {
		t.Fatalf("rule name: got %q", rule.Name)
	}
	if len(rule.Detectors) != 2 || rule.Detectors[0] != "port_scan" || rule.Detectors[1] != "ext_scan" {
		t.Fatalf("detectors: got %#v", rule.Detectors)
	}
	if len(rule.SrcAddrs) != 2 || rule.SrcAddrs[0] != "192.168.1.50" || rule.SrcAddrs[1] != "10.10.0.0/16" {
		t.Fatalf("src_addrs: got %#v", rule.SrcAddrs)
	}
}

func TestLoadSuppressionRuleRejectsUnknownDetector(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nsuppression_rules:\n  - detectors: [made_up]\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for unknown suppression detector")
	}
	if !strings.Contains(err.Error(), "suppression_rules[0].detectors[0]") {
		t.Fatalf("error: got %q, want suppression detector context", err)
	}
}

func TestLoadSuppressionRuleRejectsInvalidAddress(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nsuppression_rules:\n  - src_addrs: [not-an-ip]\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid suppression address")
	}
	if !strings.Contains(err.Error(), "suppression_rules[0].src_addrs[0]") {
		t.Fatalf("error: got %q, want suppression address context", err)
	}
}

func TestLoadSuppressionRuleRejectsEmptyMatcher(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\nsuppression_rules:\n  - name: empty\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for empty suppression matcher")
	}
	if !strings.Contains(err.Error(), "suppression_rules[0]") {
		t.Fatalf("error: got %q, want suppression rule context", err)
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}
