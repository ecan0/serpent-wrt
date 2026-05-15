package main

import (
	"bytes"
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
