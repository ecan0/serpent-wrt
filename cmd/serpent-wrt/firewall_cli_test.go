package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/enforcer"
)

func stubPacketDropPrereqs(t *testing.T, fn func(table, set string) error) {
	t.Helper()
	old := validatePacketDropPrerequisites
	validatePacketDropPrerequisites = fn
	t.Cleanup(func() { validatePacketDropPrerequisites = old })
}

func stubReconcilePolicy(t *testing.T, fn func(string, string, time.Duration, bool) (enforcer.PacketDropStatus, error)) {
	t.Helper()
	old := reconcilePacketDropPolicy
	reconcilePacketDropPolicy = fn
	t.Cleanup(func() { reconcilePacketDropPolicy = old })
}

func stubDisablePolicy(t *testing.T, fn func() error) {
	t.Helper()
	old := disablePacketDropPolicy
	disablePacketDropPolicy = fn
	t.Cleanup(func() { disablePacketDropPolicy = old })
}

func writePacketDropConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "threat-feed.txt")
	if err := os.WriteFile(feedPath, []byte("1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "serpent-wrt.yaml")
	content := fmt.Sprintf("threat_feed_path: '%s'\n%s", filepath.ToSlash(feedPath), extra)
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestRunConfigtestValidatesPacketDropPrerequisites(t *testing.T) {
	cfg := writePacketDropConfig(t, "enforcement_enabled: true\npacket_drop_enabled: true\n")
	var got [][2]string
	stubPacketDropPrereqs(t, func(table, set string) error {
		got = append(got, [2]string{table, set})
		return nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	if len(got) != 1 || got[0] != [2]string{"serpent_wrt", "blocked_ips"} {
		t.Fatalf("prerequisite validation: got %v, want serpent_wrt/blocked_ips", got)
	}
}

func TestRunConfigtestSkipsPacketDropPrerequisitesWhenDisabled(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")
	called := false
	stubPacketDropPrereqs(t, func(string, string) error {
		called = true
		return nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	if called {
		t.Fatal("detect-only configtest validated drop prerequisites")
	}
}

func TestRunConfigtestFailsWhenPacketDropPrerequisitesFail(t *testing.T) {
	cfg := writePacketDropConfig(t, "enforcement_enabled: true\npacket_drop_enabled: true\n")
	stubPacketDropPrereqs(t, func(string, string) error {
		return errors.New("firewall4 include is unavailable")
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run configtest: exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "packet drop prerequisites") ||
		!strings.Contains(stderr.String(), "firewall4 include is unavailable") {
		t.Fatalf("stderr=%q, want prerequisite failure", stderr.String())
	}
}

func TestRunConfigtestEffectiveJSONIncludesPacketDrop(t *testing.T) {
	cfg := writePacketDropConfig(t, "enforcement_enabled: true\npacket_drop_enabled: true\n")
	stubPacketDropPrereqs(t, func(string, string) error { return nil })

	var stdout, stderr bytes.Buffer
	code := run([]string{"configtest", "--config", cfg, "--effective", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run configtest: exit=%d stderr=%q", code, stderr.String())
	}
	var body map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("decode stdout=%q: %v", stdout.String(), err)
	}
	effective, ok := body["effective_config"].(map[string]any)
	if !ok {
		t.Fatalf("effective_config: got %#v", body["effective_config"])
	}
	if effective["packet_drop_enabled"] != true {
		t.Fatalf("packet_drop_enabled: got %v, want true", effective["packet_drop_enabled"])
	}
	if effective["enforcement_enabled"] != true {
		t.Fatalf("enforcement_enabled: got %v, want true", effective["enforcement_enabled"])
	}
}

func TestRunFirewallReconcileDisabledDoesNotValidatePrerequisites(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")
	prereqCalled := false
	stubPacketDropPrereqs(t, func(string, string) error {
		prereqCalled = true
		return nil
	})
	var gotEnabled []bool
	stubReconcilePolicy(t, func(table, set string, _ time.Duration, enabled bool) (enforcer.PacketDropStatus, error) {
		if table != "serpent_wrt" || set != "blocked_ips" {
			t.Fatalf("reconcile resources: got table=%q set=%q", table, set)
		}
		gotEnabled = append(gotEnabled, enabled)
		return enforcer.PacketDropStatus{Enabled: false, State: "disabled"}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"firewall", "reconcile", "--config", cfg}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run firewall reconcile: exit=%d stderr=%q", code, stderr.String())
	}
	if prereqCalled {
		t.Fatal("disabled reconcile validated drop prerequisites")
	}
	if len(gotEnabled) != 1 || gotEnabled[0] {
		t.Fatalf("reconcile enabled args: got %v, want false", gotEnabled)
	}
	if !strings.Contains(stdout.String(), "packet_drop=disabled") {
		t.Fatalf("stdout=%q, want disabled state", stdout.String())
	}
}

func TestRunFirewallReconcileEnabledValidatesBeforeApply(t *testing.T) {
	cfg := writePacketDropConfig(t, "enforcement_enabled: true\npacket_drop_enabled: true\n")
	stubPacketDropPrereqs(t, func(string, string) error {
		return errors.New("software flow offloading is enabled")
	})
	applied := false
	stubReconcilePolicy(t, func(string, string, time.Duration, bool) (enforcer.PacketDropStatus, error) {
		applied = true
		return enforcer.PacketDropStatus{}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"firewall", "reconcile", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run firewall reconcile: exit=%d, want 1", code)
	}
	if applied {
		t.Fatal("firewall mutated before prerequisite validation failed")
	}
	if !strings.Contains(stderr.String(), "software flow offloading is enabled") {
		t.Fatalf("stderr=%q, want offloading failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q, want empty", stdout.String())
	}
}

func TestRunFirewallReconcileEnabledRequiresReady(t *testing.T) {
	cfg := writePacketDropConfig(t, "enforcement_enabled: true\npacket_drop_enabled: true\n")
	stubPacketDropPrereqs(t, func(string, string) error { return nil })
	stubReconcilePolicy(t, func(string, string, time.Duration, bool) (enforcer.PacketDropStatus, error) {
		return enforcer.PacketDropStatus{Enabled: true, State: "failed", Error: "missing serpent_forward hook"}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"firewall", "reconcile", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run firewall reconcile: exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "state=failed") || !strings.Contains(stderr.String(), "missing serpent_forward hook") {
		t.Fatalf("stderr=%q, want failed active-chain detail", stderr.String())
	}
}

func TestRunFirewallReconcileSupportsGlobalConfigFlag(t *testing.T) {
	cfg := writeConfigWithFeed(t, "1.2.3.4\n")
	stubReconcilePolicy(t, func(_, _ string, _ time.Duration, enabled bool) (enforcer.PacketDropStatus, error) {
		if enabled {
			t.Fatal("global config test enabled packet drops")
		}
		return enforcer.PacketDropStatus{State: "disabled"}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"--config", cfg, "firewall", "reconcile"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run firewall reconcile: exit=%d stderr=%q", code, stderr.String())
	}
}

func TestRunFirewallReconcileInvalidConfigDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "serpent-wrt.yaml")
	if err := os.WriteFile(cfg, []byte("poll_interval: 5s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applied := false
	stubReconcilePolicy(t, func(string, string, time.Duration, bool) (enforcer.PacketDropStatus, error) {
		applied = true
		return enforcer.PacketDropStatus{}, nil
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"firewall", "reconcile", "--config", cfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run firewall reconcile: exit=%d, want 1", code)
	}
	if applied {
		t.Fatal("firewall mutated for an invalid configuration")
	}
}

func TestRunFirewallDisableIgnoresUnreadableAndInvalidConfig(t *testing.T) {
	invalidDir := t.TempDir()
	invalidCfg := filepath.Join(invalidDir, "serpent-wrt.yaml")
	if err := os.WriteFile(invalidCfg, []byte("packet_drop_enabled: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cfg  string
	}{
		{name: "missing", cfg: filepath.Join(t.TempDir(), "missing.yaml")},
		{name: "invalid", cfg: invalidCfg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disabled := false
			stubDisablePolicy(t, func() error {
				disabled = true
				return nil
			})

			var stdout, stderr bytes.Buffer
			code := run([]string{"firewall", "disable", "--config", tc.cfg}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("run firewall disable: exit=%d stderr=%q", code, stderr.String())
			}
			if !disabled {
				t.Fatal("disable did not remove the owned policy")
			}
			if !strings.Contains(stdout.String(), "packet drop policy removed") {
				t.Fatalf("stdout=%q, want removal confirmation", stdout.String())
			}
		})
	}
}

func TestRunFirewallDisableSupportsGlobalConfigFlag(t *testing.T) {
	missingCfg := filepath.Join(t.TempDir(), "missing.yaml")
	stubDisablePolicy(t, func() error { return nil })

	var stdout, stderr bytes.Buffer
	code := run([]string{"--config", missingCfg, "firewall", "disable"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run firewall disable: exit=%d stderr=%q", code, stderr.String())
	}
}

func TestRunFirewallDisableReportsFailure(t *testing.T) {
	missingCfg := filepath.Join(t.TempDir(), "missing.yaml")
	stubDisablePolicy(t, func() error { return errors.New("state directory is unreadable") })

	var stdout, stderr bytes.Buffer
	code := run([]string{"firewall", "disable", "--config", missingCfg}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run firewall disable: exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "state directory is unreadable") {
		t.Fatalf("stderr=%q, want failure detail", stderr.String())
	}
}

func TestRunFirewallRejectsMissingAndUnknownSubcommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing", args: []string{"firewall"}, want: "expected reconcile or disable"},
		{name: "unknown", args: []string{"firewall", "flush"}, want: `unknown command "flush"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit=%d, want 2", code)
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr=%q, want %q", stderr.String(), tc.want)
			}
		})
	}
}

func TestRunFirewallRejectsUnexpectedArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "reconcile", args: []string{"firewall", "reconcile", "extra"}},
		{name: "disable", args: []string{"firewall", "disable", "extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit=%d, want 2", code)
			}
			if !strings.Contains(stderr.String(), "unexpected argument") {
				t.Fatalf("stderr=%q, want unexpected argument", stderr.String())
			}
		})
	}
}
