package enforcer

import (
	"net"
	"testing"
	"time"
)

func TestFormatDurationHours(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{time.Hour, "1h"},
		{2 * time.Hour, "2h"},
		{24 * time.Hour, "24h"},
	}
	for _, tc := range cases {
		if got := formatDuration(tc.d); got != tc.want {
			t.Errorf("formatDuration(%v): got %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFormatDurationMinutes(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Minute, "30m"},
		{5 * time.Minute, "5m"},
	}
	for _, tc := range cases {
		if got := formatDuration(tc.d); got != tc.want {
			t.Errorf("formatDuration(%v): got %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFormatDurationSeconds(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{90 * time.Second, "90s"},
		{45 * time.Second, "45s"},
		{1 * time.Second, "1s"},
	}
	for _, tc := range cases {
		if got := formatDuration(tc.d); got != tc.want {
			t.Errorf("formatDuration(%v): got %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestEnsureSetScript(t *testing.T) {
	got := ensureSetScript("serpent_wrt", "blocked_ips")
	want := "add table inet serpent_wrt\n" +
		"add set inet serpent_wrt blocked_ips { type ipv4_addr; flags timeout; }\n"
	if got != want {
		t.Fatalf("ensureSetScript:\ngot  %q\nwant %q", got, want)
	}
}

func TestBlockScript(t *testing.T) {
	got := blockScript("serpent_wrt", "blocked_ips", "1.2.3.4", 90*time.Second)
	want := "add element inet serpent_wrt blocked_ips { 1.2.3.4 timeout 90s }\n"
	if got != want {
		t.Fatalf("blockScript:\ngot  %q\nwant %q", got, want)
	}
}

func TestNew(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	if e == nil {
		t.Fatal("New returned nil")
	}
}

func TestIsBlockedEmpty(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("1.2.3.4")
	if e.IsBlocked(ip) {
		t.Error("IsBlocked should be false for fresh enforcer")
	}
}

func TestIsBlockedIPv6(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("::1")
	if e.IsBlocked(ip) {
		t.Error("IsBlocked should always return false for IPv6")
	}
}

func TestBlockIPv6NoOp(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("::1")
	if err := e.Block(ip); err != nil {
		t.Errorf("Block(IPv6) should be a no-op, got error: %v", err)
	}
	if e.IsBlocked(ip) {
		t.Error("IPv6 should not appear as blocked")
	}
}

func TestPruneEmpty(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	e.Prune() // must not panic on empty map
}

func TestPruneExpired(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("1.2.3.4")

	// Inject an already-expired entry directly into the map.
	e.mu.Lock()
	e.blocked[ip.To4().String()] = time.Now().Add(-time.Second)
	e.mu.Unlock()

	e.Prune()

	if e.IsBlocked(ip) {
		t.Error("expected expired entry to be removed by Prune")
	}
}

func TestPruneKeepsActive(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("5.5.5.5")

	// Inject an active (not yet expired) entry.
	e.mu.Lock()
	e.blocked[ip.To4().String()] = time.Now().Add(time.Hour)
	e.mu.Unlock()

	e.Prune()

	if !e.IsBlocked(ip) {
		t.Error("Prune should not remove active entries")
	}
}

func TestIsBlockedAfterDirectInject(t *testing.T) {
	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("9.9.9.9")

	e.mu.Lock()
	e.blocked[ip.To4().String()] = time.Now().Add(time.Hour)
	e.mu.Unlock()

	if !e.IsBlocked(ip) {
		t.Error("IsBlocked should return true for injected active entry")
	}
}
