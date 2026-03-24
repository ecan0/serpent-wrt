package state_test

import (
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/state"
)

func TestTrackerAdd(t *testing.T) {
	tr := state.NewTracker(10*time.Second, 100)

	if n := tr.Add("src1", "dst1"); n != 1 {
		t.Fatalf("first add: got %d, want 1", n)
	}
	if n := tr.Add("src1", "dst2"); n != 2 {
		t.Fatalf("second distinct value: got %d, want 2", n)
	}
	// Duplicate value should not increase count.
	if n := tr.Add("src1", "dst1"); n != 2 {
		t.Fatalf("duplicate add: got %d, want 2", n)
	}
}

func TestTrackerSeparateKeys(t *testing.T) {
	tr := state.NewTracker(10*time.Second, 100)
	tr.Add("src1", "dst1")
	tr.Add("src1", "dst2")

	// Different key starts fresh.
	if n := tr.Add("src2", "dst1"); n != 1 {
		t.Fatalf("new key: got %d, want 1", n)
	}
}

func TestTrackerWindowExpiry(t *testing.T) {
	tr := state.NewTracker(50*time.Millisecond, 100)
	tr.Add("src1", "dst1")
	time.Sleep(80 * time.Millisecond)

	// Window expired — count resets.
	if n := tr.Add("src1", "dst2"); n != 1 {
		t.Fatalf("after expiry: got %d, want 1", n)
	}
}

func TestTrackerPrune(t *testing.T) {
	tr := state.NewTracker(50*time.Millisecond, 100)
	tr.Add("src1", "dst1")
	time.Sleep(80 * time.Millisecond)
	tr.Prune() // expired entry removed

	// After prune, fresh add should return 1.
	if n := tr.Add("src1", "dst2"); n != 1 {
		t.Fatalf("after prune: got %d, want 1", n)
	}
}

func TestTrackerEviction(t *testing.T) {
	tr := state.NewTracker(10*time.Second, 2)
	tr.Add("src1", "dst1")
	tr.Add("src2", "dst1")
	// Third key should evict one of the first two without panicking.
	tr.Add("src3", "dst1")
	// Adding a fourth should also be safe.
	tr.Add("src4", "dst1")
}
