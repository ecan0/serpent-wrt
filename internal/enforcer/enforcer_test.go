package enforcer

import (
	"errors"
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

func TestBlockTracksSuccessfulBlock(t *testing.T) {
	var scripts []string
	restore := stubNftScript(t, func(script string) error {
		scripts = append(scripts, script)
		return nil
	})
	defer restore()

	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("1.2.3.4")
	if err := e.Block(ip); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !e.IsBlocked(ip) {
		t.Fatal("successful block should be tracked")
	}
	if err := e.Block(ip); err != nil {
		t.Fatalf("duplicate Block: %v", err)
	}
	if len(scripts) != 1 {
		t.Fatalf("nft scripts: got %d, want 1", len(scripts))
	}
}

func TestBlockDoesNotTrackFailedBlock(t *testing.T) {
	restore := stubNftScript(t, func(_ string) error {
		return errors.New("nft failed")
	})
	defer restore()

	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("1.2.3.4")
	if err := e.Block(ip); err == nil {
		t.Fatal("expected block error")
	}
	if e.IsBlocked(ip) {
		t.Fatal("failed block should not be tracked")
	}
}

func TestCheckUnavailable(t *testing.T) {
	restore := stubNft(t, errors.New("missing"), nil)
	defer restore()

	e := New("serpent_wrt", "blocked_ips", time.Hour)
	check := e.Check()
	if check.Available {
		t.Fatal("expected nft to be unavailable")
	}
	if check.Error != "nft not found in PATH" {
		t.Fatalf("error: got %q, want nft not found in PATH", check.Error)
	}
}

func TestCheckReady(t *testing.T) {
	var calls [][]string
	restore := stubNft(t, nil, func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	})
	defer restore()

	e := New("serpent_wrt", "blocked_ips", time.Hour)
	check := e.Check()
	if !check.Available || !check.TablePresent || !check.SetPresent || check.Error != "" {
		t.Fatalf("check: got %+v, want ready", check)
	}
	if len(calls) != 2 {
		t.Fatalf("nft calls: got %d, want 2", len(calls))
	}
	wantTable := []string{"list", "table", "inet", "serpent_wrt"}
	wantSet := []string{"list", "set", "inet", "serpent_wrt", "blocked_ips"}
	if !sameStrings(calls[0], wantTable) || !sameStrings(calls[1], wantSet) {
		t.Fatalf("calls: got %#v, want %#v then %#v", calls, wantTable, wantSet)
	}
}

func TestCheckMissingSet(t *testing.T) {
	restore := stubNft(t, nil, func(args ...string) error {
		if len(args) > 1 && args[1] == "set" {
			return errors.New("set missing")
		}
		return nil
	})
	defer restore()

	e := New("serpent_wrt", "blocked_ips", time.Hour)
	check := e.Check()
	if !check.Available || !check.TablePresent || check.SetPresent {
		t.Fatalf("check: got %+v, want missing set", check)
	}
	if check.Error != "set missing" {
		t.Fatalf("error: got %q, want set missing", check.Error)
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

func stubNft(t *testing.T, lookPathErr error, runner func(args ...string) error) func() {
	t.Helper()
	oldLookPath := lookPath
	oldRunNftCommand := runNftCommand
	lookPath = func(file string) (string, error) {
		if file != "nft" {
			t.Fatalf("lookPath called with %q, want nft", file)
		}
		if lookPathErr != nil {
			return "", lookPathErr
		}
		return "/usr/sbin/nft", nil
	}
	if runner != nil {
		runNftCommand = runner
	}
	return func() {
		lookPath = oldLookPath
		runNftCommand = oldRunNftCommand
	}
}

func stubNftScript(t *testing.T, runner func(string) error) func() {
	t.Helper()
	oldRunNftScript := runNftScript
	runNftScript = runner
	return func() {
		runNftScript = oldRunNftScript
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
