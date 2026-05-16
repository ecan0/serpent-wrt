package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfigtestSuccess(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n203.0.113.0/24\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "config OK") {
		t.Fatalf("stdout=%q, want config OK", stdout.String())
	}
	if !strings.Contains(stdout.String(), "entries=2") {
		t.Fatalf("stdout=%q, want feed entry count", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
}

func TestRunConfigtestSupportsGlobalConfigFlag(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"--config", cfg, "configtest"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "entries=1") {
		t.Fatalf("stdout=%q, want feed entry count", stdout.String())
	}
}

func TestRunConfigtestEffectivePrintsResolvedConfig(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "threat-feed.txt")
	if err := os.WriteFile(feedPath, []byte("1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	content := fmt.Sprintf(`threat_feed_path: '%s'
profile: quiet
lease_enrichment: true
lan_cidrs:
  - 192.168.1.0/24
self_ips:
  - 192.168.1.1
detectors:
  scan:
    distinct_port_threshold: 12
suppression_rules:
  - name: expected scan
    detectors: [port_scan]
    src_addrs: [192.168.1.50]
`, filepath.ToSlash(feedPath))
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg, "--effective"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"config OK",
		"effective config:",
		"profile: quiet",
		"poll_interval: 5s",
		"dnsmasq_leases_path: /tmp/dhcp.leases",
		"block_duration: 1h",
		"dedup_window: 5m",
		"distinct_dst_threshold: 100",
		"distinct_port_threshold: 12",
		"min_interval: 10s",
		"name: expected scan",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout=%q, want %q", out, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
}

func TestRunConfigtestEffectiveJSONPrintsResolvedConfig(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "threat-feed.txt")
	if err := os.WriteFile(feedPath, []byte("1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	content := fmt.Sprintf(`threat_feed_path: '%s'
profile: quiet
lease_enrichment: true
lan_cidrs:
  - 192.168.1.0/24
self_ips:
  - 192.168.1.1
suppression_rules:
  - name: expected scan
    detectors: [port_scan]
    src_addrs: [192.168.1.50]
`, filepath.ToSlash(feedPath))
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg, "--effective", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}

	var body map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("decode stdout=%q: %v", stdout.String(), err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status: got %v, want ok", body["status"])
	}
	if body["feed_entries"] != float64(1) {
		t.Fatalf("feed_entries: got %v, want 1", body["feed_entries"])
	}
	effective, ok := body["effective_config"].(map[string]any)
	if !ok {
		t.Fatalf("effective_config: got %#v", body["effective_config"])
	}
	if effective["profile"] != "quiet" {
		t.Fatalf("profile: got %v, want quiet", effective["profile"])
	}
	if effective["dnsmasq_leases_path"] != "/tmp/dhcp.leases" {
		t.Fatalf("dnsmasq_leases_path: got %v", effective["dnsmasq_leases_path"])
	}
	detectors := effective["detectors"].(map[string]any)
	fanout := detectors["fanout"].(map[string]any)
	if fanout["distinct_dst_threshold"] != float64(100) {
		t.Fatalf("fanout threshold: got %v, want 100", fanout["distinct_dst_threshold"])
	}
	beacon := detectors["beacon"].(map[string]any)
	excludePorts, ok := beacon["exclude_ports"].([]any)
	if !ok || len(excludePorts) != 0 {
		t.Fatalf("exclude_ports: got %#v, want empty array", beacon["exclude_ports"])
	}
	rules := effective["suppression_rules"].([]any)
	rule := rules[0].(map[string]any)
	if rule["src_addrs"] == nil {
		t.Fatalf("suppression rule keys: got %#v, want src_addrs", rule)
	}
}

func TestRunConfigtestRejectsJSONFormatWithoutEffective(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg, "--format", "json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run configtest: exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--format json requires --effective") {
		t.Fatalf("stderr=%q, want format/effective error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q, want empty", stdout.String())
	}
}

func TestRunConfigtestRejectsInvalidFormat(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg, "--effective", "--format", "yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run configtest: exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "invalid format") {
		t.Fatalf("stderr=%q, want invalid format", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q, want empty", stdout.String())
	}
}

func TestRunConfigtestEffectiveJSONInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	if err := os.WriteFile(cfg, []byte("poll_interval: 5s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg, "--effective", "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run configtest: exit=%d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty for json errors", stderr.String())
	}
	var body map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("decode stdout=%q: %v", stdout.String(), err)
	}
	if body["status"] != "error" {
		t.Fatalf("status: got %v, want error", body["status"])
	}
	if !strings.Contains(fmt.Sprint(body["error"]), "threat_feed_path is required") {
		t.Fatalf("error: got %v", body["error"])
	}
}

func TestRunConfigtestPrintsWarnings(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "threat-feed.txt")
	if err := os.WriteFile(feedPath, []byte("1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	content := fmt.Sprintf(`threat_feed_path: '%s'
api_enabled: true
api_bind: 0.0.0.0:8080
enforcement_enabled: true
profile: paranoid
suppression_rules:
  - name: broad scan silence
    detectors: [port_scan]
`, filepath.ToSlash(feedPath))
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"config OK",
		"config warning",
		"lan_cidrs is empty",
		"api_bind \"0.0.0.0:8080\" is not loopback-only",
		"profile paranoid with enforcement_enabled true",
		"matches only by detector",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout=%q, want %q", out, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
}

func TestRunConfigtestFailsForInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	if err := os.WriteFile(cfg, []byte("poll_interval: 5s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run configtest: exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "threat_feed_path is required") {
		t.Fatalf("stderr=%q, want missing feed path error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q, want empty", stdout.String())
	}
}

func TestRunConfigtestFailsForMissingFeed(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	missingFeed := filepath.Join(dir, "missing-feed.txt")
	content := fmt.Sprintf("threat_feed_path: '%s'\n", filepath.ToSlash(missingFeed))
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run configtest: exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "threat feed") {
		t.Fatalf("stderr=%q, want threat feed context", stderr.String())
	}
}

func TestRunConfigtestFailsForInvalidFeed(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\nnot-an-ip\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run configtest: exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "line 2") || !strings.Contains(stderr.String(), "not-an-ip") {
		t.Fatalf("stderr=%q, want invalid feed line context", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q, want empty", stdout.String())
	}
}

func TestRunNftcheckSkipsWhenEnforcementDisabled(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"nftcheck", "--config", cfg}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run nftcheck: exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "nft check skipped") {
		t.Fatalf("stdout=%q, want nft check skipped", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
}

func TestRunNftcheckSupportsGlobalConfigFlag(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"--config", cfg, "nftcheck"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run nftcheck: exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "enforcement disabled") {
		t.Fatalf("stdout=%q, want enforcement disabled", stdout.String())
	}
}

func TestRunNftcheckJSONSkipsWhenEnforcementDisabled(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"nftcheck", "--config", cfg, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run nftcheck: exit=%d stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty", stderr.String())
	}
	var body map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("decode stdout=%q: %v", stdout.String(), err)
	}
	if body["status"] != "skipped" {
		t.Fatalf("status: got %v, want skipped", body["status"])
	}
	if body["enforcement_enabled"] != false {
		t.Fatalf("enforcement_enabled: got %v, want false", body["enforcement_enabled"])
	}
	if body["table"] != "serpent_wrt" || body["set"] != "blocked_ips" {
		t.Fatalf("table/set: %+v", body)
	}
	if body["diagnostic"] != "enforcement disabled" {
		t.Fatalf("diagnostic: got %v", body["diagnostic"])
	}
}

func TestRunNftcheckRejectsInvalidFormat(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"nftcheck", "--config", cfg, "--format", "yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run nftcheck: exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "invalid format") {
		t.Fatalf("stderr=%q, want invalid format", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q, want empty", stdout.String())
	}
}

func TestRunNftcheckJSONInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	if err := os.WriteFile(cfg, []byte("poll_interval: 5s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"nftcheck", "--config", cfg, "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run nftcheck: exit=%d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q, want empty for json errors", stderr.String())
	}
	var body map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("decode stdout=%q: %v", stdout.String(), err)
	}
	if body["status"] != "error" {
		t.Fatalf("status: got %v, want error", body["status"])
	}
	if !strings.Contains(fmt.Sprint(body["error"]), "threat_feed_path is required") {
		t.Fatalf("error: got %v", body["error"])
	}
}

func TestRunNftcheckFailsForInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	if err := os.WriteFile(cfg, []byte("poll_interval: 5s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"nftcheck", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run nftcheck: exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "threat_feed_path is required") {
		t.Fatalf("stderr=%q, want missing feed path error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q, want empty", stdout.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run unknown command: exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr=%q, want unknown command", stderr.String())
	}
}

func writeConfigWithFeed(t *testing.T, feedContent string) string {
	t.Helper()
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "threat-feed.txt")
	if err := os.WriteFile(feedPath, []byte(feedContent), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "serpent-wrt.yaml")
	content := fmt.Sprintf("threat_feed_path: '%s'\nlan_cidrs:\n  - 192.168.1.0/24\nself_ips:\n  - 192.168.1.1\n", filepath.ToSlash(feedPath))
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}
