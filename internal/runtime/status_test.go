package runtime

import (
	"errors"
	"testing"

	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/enforcer"
	"github.com/ecan0/serpent-wrt/internal/events"
)

func TestGetStatusInitial(t *testing.T) {
	e := testEngine(t)
	s := e.GetStatus()
	if s.Status != "ok" {
		t.Errorf("Status: got %q, want ok", s.Status)
	}
	if s.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
	if s.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds: got %d, want non-negative", s.UptimeSeconds)
	}
	if s.Feed.Path != "../../testdata/threat-feed.txt" {
		t.Errorf("Feed.Path: got %q", s.Feed.Path)
	}
	if s.Enforcement.Enabled {
		t.Error("Enforcement.Enabled should be false")
	}
	if s.Enforcement.Nft.SetupState != nftSetupDisabled {
		t.Errorf("nft setup state: got %q, want %q", s.Enforcement.Nft.SetupState, nftSetupDisabled)
	}
	if s.Enforcement.Nft.Checked {
		t.Error("nft check should be skipped when enforcement is disabled")
	}
	if s.Enforcement.Nft.CheckState != "disabled" {
		t.Errorf("nft check state: got %q, want disabled", s.Enforcement.Nft.CheckState)
	}
	if s.Runtime.Version != "dev" {
		t.Errorf("Runtime.Version: got %q, want dev", s.Runtime.Version)
	}
	if s.Runtime.SuppressionRules != 0 {
		t.Errorf("Runtime.SuppressionRules: got %d, want 0", s.Runtime.SuppressionRules)
	}
	if !s.Detectors.FeedMatch.Enabled {
		t.Error("FeedMatch should report enabled")
	}
	if s.Detectors.ExtScan.DistinctPortThreshold != 20 {
		t.Errorf("ExtScan threshold: got %d, want 20", s.Detectors.ExtScan.DistinctPortThreshold)
	}
	if s.Detectors.BruteForce.Threshold != 5 {
		t.Errorf("BruteForce threshold: got %d, want 5", s.Detectors.BruteForce.Threshold)
	}
}

func TestGetStatusSuppressionRuleCount(t *testing.T) {
	cfg := testConfig()
	cfg.SuppressionRules = []config.SuppressionRule{
		{Detectors: []string{"beacon"}},
		{SrcAddrs: []string{"192.168.1.50"}},
	}
	e := NewEngine(cfg, events.NewLogger(nil))

	s := e.GetStatus()
	if s.Runtime.SuppressionRules != 2 {
		t.Errorf("Runtime.SuppressionRules: got %d, want 2", s.Runtime.SuppressionRules)
	}
}

func TestNftCheckState(t *testing.T) {
	cases := []struct {
		name           string
		setupState     string
		check          enforcer.NftCheck
		wantState      string
		wantDiagnostic string
	}{
		{
			name:           "unavailable",
			check:          enforcer.NftCheck{Available: false},
			wantState:      "unavailable",
			wantDiagnostic: "nft CLI is unavailable; enforcement cannot apply blocks",
		},
		{
			name:           "missing table before setup",
			check:          enforcer.NftCheck{Available: true},
			wantState:      "missing_table",
			wantDiagnostic: "nft table is not present yet",
		},
		{
			name:       "missing set after setup",
			setupState: nftSetupReady,
			check: enforcer.NftCheck{
				Available:    true,
				TablePresent: true,
			},
			wantState:      "missing_set",
			wantDiagnostic: "nft set is missing after setup; a firewall reload may have removed serpent-wrt enforcement state",
		},
		{
			name:       "ready",
			setupState: nftSetupReady,
			check: enforcer.NftCheck{
				Available:    true,
				TablePresent: true,
				SetPresent:   true,
			},
			wantState:      "ready",
			wantDiagnostic: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotState, gotDiagnostic := nftCheckState(tc.setupState, tc.check)
			if gotState != tc.wantState {
				t.Fatalf("state: got %q, want %q", gotState, tc.wantState)
			}
			if gotDiagnostic != tc.wantDiagnostic {
				t.Fatalf("diagnostic: got %q, want %q", gotDiagnostic, tc.wantDiagnostic)
			}
		})
	}
}

func TestGetStatusBuildInfo(t *testing.T) {
	e := testEngine(t)
	e.SetBuildInfo(BuildInfo{
		Version:   "v0.1.0",
		Commit:    "abc123",
		BuildDate: "2026-05-06",
	})

	s := e.GetStatus()
	if s.Runtime.Version != "v0.1.0" {
		t.Errorf("Runtime.Version: got %q, want v0.1.0", s.Runtime.Version)
	}
	if s.Runtime.Commit != "abc123" {
		t.Errorf("Runtime.Commit: got %q, want abc123", s.Runtime.Commit)
	}
	if s.Runtime.BuildDate != "2026-05-06" {
		t.Errorf("Runtime.BuildDate: got %q, want 2026-05-06", s.Runtime.BuildDate)
	}
}

func TestGetStatusNftSetupFailure(t *testing.T) {
	cfg := testConfig()
	cfg.EnforcementEnabled = true
	e := NewEngine(cfg, events.NewLogger(nil))

	s := e.GetStatus()
	if s.Enforcement.Nft.SetupState != nftSetupNotAttempted {
		t.Errorf("initial setup state: got %q, want %q", s.Enforcement.Nft.SetupState, nftSetupNotAttempted)
	}

	e.setNftSetupState(nftSetupFailed, errors.New("nft missing"))
	s = e.GetStatus()
	if s.Enforcement.Nft.SetupState != nftSetupFailed {
		t.Errorf("failed setup state: got %q, want %q", s.Enforcement.Nft.SetupState, nftSetupFailed)
	}
	if s.Enforcement.Nft.LastError != "nft missing" {
		t.Errorf("last error: got %q, want nft missing", s.Enforcement.Nft.LastError)
	}
}
