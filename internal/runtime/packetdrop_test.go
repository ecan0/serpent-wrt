package runtime

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/detector"
	"github.com/ecan0/serpent-wrt/internal/enforcer"
	"github.com/ecan0/serpent-wrt/internal/events"
	"github.com/ecan0/serpent-wrt/internal/flow"
)

type enforcerStubs struct {
	ensure    func(*enforcer.Enforcer) (bool, error)
	block     func(*enforcer.Enforcer, net.IP) error
	reconcile func(*enforcer.Enforcer, bool) (enforcer.PacketDropStatus, error)
}

func stubEnforcer(t *testing.T, stubs enforcerStubs) {
	t.Helper()
	oldEnsure, oldBlock := ensureEnforcerResources, blockEnforcerSource
	oldReconcile := reconcileEnforcerPacketDrop
	if stubs.ensure != nil {
		ensureEnforcerResources = stubs.ensure
	}
	if stubs.block != nil {
		blockEnforcerSource = stubs.block
	}
	if stubs.reconcile != nil {
		reconcileEnforcerPacketDrop = stubs.reconcile
	}
	t.Cleanup(func() {
		ensureEnforcerResources = oldEnsure
		blockEnforcerSource = oldBlock
		reconcileEnforcerPacketDrop = oldReconcile
	})
}

// stubEnsureResourcesOK keeps enforcement tests off the production firewall
// lock and nft exec path while preserving the block attempt under test.
func stubEnsureResourcesOK(t *testing.T) {
	t.Helper()
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) { return false, nil },
	})
}

func testDetection(src string) *detector.Detection {
	return &detector.Detection{
		Type:       "feed_match",
		Severity:   detector.SeverityHigh,
		Confidence: 95,
		Reason:     detector.ReasonThreatFeedDestination,
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP("1.2.3.4"),
		DstPort:    443,
		Message:    "test",
	}
}

func TestHandleDetectionEnsuresResourcesBeforeEachBlock(t *testing.T) {
	cfg := testConfig()
	cfg.EnforcementEnabled = true
	engine := NewEngine(cfg, events.NewLogger(nil, events.LevelInfo))

	var calls []string
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			calls = append(calls, "ensure")
			return false, nil
		},
		block: func(_ *enforcer.Enforcer, _ net.IP) error {
			calls = append(calls, "block")
			return nil
		},
		reconcile: func(*enforcer.Enforcer, bool) (enforcer.PacketDropStatus, error) {
			t.Fatal("reconcile must not run when resources were not recreated")
			return enforcer.PacketDropStatus{}, nil
		},
	})

	engine.handleDetection(testDetection("192.168.1.20"))
	engine.handleDetection(testDetection("192.168.1.21"))

	want := []string{"ensure", "block", "ensure", "block"}
	if len(calls) != len(want) {
		t.Fatalf("calls: got %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("call order: got %v, want %v", calls, want)
		}
	}
	if got := engine.GetStats().BlocksApplied; got != 2 {
		t.Fatalf("blocks applied: got %d, want 2", got)
	}
}

func TestHandleDetectionReconcilesPacketDropAfterResourceLoss(t *testing.T) {
	cfg := testConfig()
	cfg.EnforcementEnabled = true
	cfg.PacketDropEnabled = true
	engine := NewEngine(cfg, events.NewLogger(nil, events.LevelInfo))

	var calls []string
	var reconcileArgs []bool
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			calls = append(calls, "ensure")
			return true, nil
		},
		reconcile: func(_ *enforcer.Enforcer, enabled bool) (enforcer.PacketDropStatus, error) {
			calls = append(calls, "reconcile")
			reconcileArgs = append(reconcileArgs, enabled)
			return enforcer.PacketDropStatus{Enabled: true, State: "ready"}, nil
		},
		block: func(_ *enforcer.Enforcer, _ net.IP) error {
			calls = append(calls, "block")
			return nil
		},
	})

	engine.handleDetection(testDetection("192.168.1.20"))

	want := []string{"ensure", "reconcile", "block"}
	if len(calls) != len(want) {
		t.Fatalf("calls: got %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("call order: got %v, want %v", calls, want)
		}
	}
	if len(reconcileArgs) != 1 || !reconcileArgs[0] {
		t.Fatalf("reconcile args: got %v, want enabled=true", reconcileArgs)
	}
	if got := engine.GetStats().BlocksApplied; got != 1 {
		t.Fatalf("blocks applied: got %d, want 1", got)
	}
}

func TestHandleDetectionRecreatedResourcesWithoutPolicyDoesNotReconcile(t *testing.T) {
	cfg := testConfig()
	cfg.EnforcementEnabled = true
	engine := NewEngine(cfg, events.NewLogger(nil, events.LevelInfo))

	var calls []string
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			calls = append(calls, "ensure")
			return true, nil
		},
		reconcile: func(*enforcer.Enforcer, bool) (enforcer.PacketDropStatus, error) {
			t.Fatal("reconciled a policy that is not enabled")
			return enforcer.PacketDropStatus{}, nil
		},
		block: func(*enforcer.Enforcer, net.IP) error {
			calls = append(calls, "block")
			return nil
		},
	})

	engine.handleDetection(testDetection("192.168.1.20"))
	if len(calls) != 2 || calls[0] != "ensure" || calls[1] != "block" {
		t.Fatalf("calls: got %v, want [ensure block]", calls)
	}
}

func TestHandleDetectionResourceFailureSkipsBlockAndReconcile(t *testing.T) {
	cfg := testConfig()
	cfg.EnforcementEnabled = true
	cfg.PacketDropEnabled = true
	engine := NewEngine(cfg, events.NewLogger(nil, events.LevelInfo))

	blocked := false
	reconciled := false
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			return false, errors.New("nft not found")
		},
		block: func(*enforcer.Enforcer, net.IP) error {
			blocked = true
			return nil
		},
		reconcile: func(*enforcer.Enforcer, bool) (enforcer.PacketDropStatus, error) {
			reconciled = true
			return enforcer.PacketDropStatus{}, nil
		},
	})

	engine.handleDetection(testDetection("192.168.1.20"))

	if blocked {
		t.Fatal("block attempted after resource verification failed")
	}
	if reconciled {
		t.Fatal("packet drop reconciled after resource verification failed")
	}
	stats := engine.GetStats()
	if stats.BlocksFailed != 1 || stats.BlocksApplied != 0 {
		t.Fatalf("block counters: got failed=%d applied=%d", stats.BlocksFailed, stats.BlocksApplied)
	}
}

func TestDetectOnlyDoesNotTouchEnforcementResources(t *testing.T) {
	engine := testEngine(t)

	touched := false
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			touched = true
			return false, nil
		},
		reconcile: func(*enforcer.Enforcer, bool) (enforcer.PacketDropStatus, error) {
			touched = true
			return enforcer.PacketDropStatus{}, nil
		},
		block: func(*enforcer.Enforcer, net.IP) error {
			touched = true
			return nil
		},
	})

	engine.handleDetection(testDetection("192.168.1.20"))
	if touched {
		t.Fatal("detect-only detection touched enforcement resources")
	}
	if got := engine.GetStats().BlocksApplied; got != 0 {
		t.Fatalf("blocks applied: got %d, want 0", got)
	}
}

func TestRunCreatesResourcesThenReconcilesPacketDrop(t *testing.T) {
	cfg := testConfig()
	cfg.EnforcementEnabled = true
	cfg.PacketDropEnabled = true
	cfg.PollInterval = time.Millisecond
	engine := NewEngine(cfg, events.NewLogger(nil, events.LevelInfo))

	var calls []string
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			calls = append(calls, "ensure")
			return true, nil
		},
		reconcile: func(_ *enforcer.Enforcer, enabled bool) (enforcer.PacketDropStatus, error) {
			if !enabled {
				t.Fatal("startup reconcile did not enable the configured policy")
			}
			calls = append(calls, "reconcile")
			return enforcer.PacketDropStatus{Enabled: true, State: "ready"}, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	engine.collectSnapshot = func() ([]flow.FlowRecord, error) {
		cancel()
		return nil, nil
	}
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(calls) != 2 || calls[0] != "ensure" || calls[1] != "reconcile" {
		t.Fatalf("startup order: got %v, want [ensure reconcile]", calls)
	}
	engine.nftMu.Lock()
	state := engine.nftSetupState
	engine.nftMu.Unlock()
	if state != nftSetupReady {
		t.Fatalf("nft setup state: got %q, want ready", state)
	}
}

func TestRunResourceFailureSkipsPacketDropReconcile(t *testing.T) {
	cfg := testConfig()
	cfg.EnforcementEnabled = true
	cfg.PacketDropEnabled = true
	cfg.PollInterval = time.Millisecond
	engine := NewEngine(cfg, events.NewLogger(nil, events.LevelInfo))

	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			return false, errors.New("nft not found")
		},
		reconcile: func(*enforcer.Enforcer, bool) (enforcer.PacketDropStatus, error) {
			t.Fatal("reconciled packet drops without nft resources")
			return enforcer.PacketDropStatus{}, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	engine.collectSnapshot = func() ([]flow.FlowRecord, error) {
		cancel()
		return nil, nil
	}
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	engine.nftMu.Lock()
	state := engine.nftSetupState
	engine.nftMu.Unlock()
	if state != nftSetupFailed {
		t.Fatalf("nft setup state: got %q, want failed", state)
	}
}

func TestRunDetectOnlyDoesNotCreateOrReconcile(t *testing.T) {
	engine := testEngine(t)
	engine.cfg.PollInterval = time.Millisecond

	touched := false
	stubEnforcer(t, enforcerStubs{
		ensure: func(*enforcer.Enforcer) (bool, error) {
			touched = true
			return false, nil
		},
		reconcile: func(*enforcer.Enforcer, bool) (enforcer.PacketDropStatus, error) {
			touched = true
			return enforcer.PacketDropStatus{}, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	engine.collectSnapshot = func() ([]flow.FlowRecord, error) {
		cancel()
		return nil, nil
	}
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if touched {
		t.Fatal("detect-only startup created or reconciled enforcement resources")
	}
}
