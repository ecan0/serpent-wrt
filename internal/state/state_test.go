package state_test

import (
	"fmt"
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

	// Sliding window: old value expired, new add starts at 1.
	if n := tr.Add("src1", "dst2"); n != 1 {
		t.Fatalf("after expiry: got %d, want 1", n)
	}
}

func TestTrackerSlidingWindow(t *testing.T) {
	tr := state.NewTracker(100*time.Millisecond, 100)
	tr.Add("src1", "dst1")
	tr.Add("src1", "dst2")
	// Both values are within window → count is 2.
	if n := tr.Add("src1", "dst3"); n != 3 {
		t.Fatalf("sliding add: got %d, want 3", n)
	}
	time.Sleep(120 * time.Millisecond)
	// All three values have expired. New add should count 1.
	if n := tr.Add("src1", "dst4"); n != 1 {
		t.Fatalf("after all expired: got %d, want 1", n)
	}
}

func TestTrackerSlidingWindowPartialExpiry(t *testing.T) {
	tr := state.NewTracker(120*time.Millisecond, 100)
	tr.Add("src1", "dst1")
	tr.Add("src1", "dst2")
	time.Sleep(80 * time.Millisecond)
	// dst1 and dst2 still within window; dst3 is new → count 3.
	if n := tr.Add("src1", "dst3"); n != 3 {
		t.Fatalf("partial expiry: got %d, want 3", n)
	}
	time.Sleep(60 * time.Millisecond)
	// dst1 and dst2 now expired (>120ms old); dst3 still fresh → count 1.
	if n := tr.Add("src1", "dst4"); n != 2 {
		t.Fatalf("partial expiry second: got %d, want 2", n)
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

func BenchmarkTrackerAddParallel(b *testing.B) {
	t := state.NewTracker(60*time.Second, 1024)
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			t.Add(fmt.Sprintf("key-%d", i%100), fmt.Sprintf("val-%d", i))
			i++
		}
	})
}
