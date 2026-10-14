package enforcer

import (
	"errors"
	"net"
	"strings"
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

func TestBlockIPv6TracksSuccessfulBlock(t *testing.T) {
	var applied string
	restore := stubNftScript(t, func(script string) error {
		applied = script
		return nil
	})
	defer restore()

	e := New("serpent_wrt", "blocked_ips", time.Hour)
	ip := net.ParseIP("2001:db8::1")
	if err := e.Block(ip); err != nil {
		t.Fatalf("Block(IPv6): %v", err)
	}
	if !e.IsBlocked(ip) {
		t.Fatal("IPv6 should appear as blocked")
	}
	if !strings.Contains(applied, "blocked_ips_v6") || strings.Contains(applied, "blocked_ips_v4") {
		t.Fatalf("IPv6 block used the wrong set: %s", applied)
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
	if !strings.Contains(scripts[0], "blocked_ips_v4") || strings.Contains(scripts[0], "blocked_ips_v6") {
		t.Fatalf("IPv4 block used the wrong set: %s", scripts[0])
	}
	if len(scripts) != 1 {
		t.Fatalf("nft scripts: got %d, want 1", len(scripts))
	}
}

func TestEnsureSetDoesNotApplyWhenParserRejectsDefinitions(t *testing.T) {
	restoreNft := stubNft(t, nil, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" {
			return errors.New("table missing")
		}
		t.Fatalf("unexpected nft query: %#v", args)
		return nil
	})
	defer restoreNft()
	applied := false
	restoreApply := stubNftScript(t, func(string) error {
		applied = true
		return nil
	})
	defer restoreApply()
	restoreCheck := stubNftScriptCheck(t, func(script string) error {
		if !strings.Contains(script, "type ipv4_addr") || !strings.Contains(script, "type ipv6_addr") {
			t.Fatalf("validation omitted an address family: %s", script)
		}
		return errors.New("unknown datatype inet_addr")
	})
	defer restoreCheck()

	err := New("serpent_wrt", "blocked_ips", time.Hour).EnsureSet()
	if err == nil || !strings.Contains(err.Error(), "unknown datatype inet_addr") {
		t.Fatalf("EnsureSet error: got %v, want parser diagnostic", err)
	}
	if applied {
		t.Fatal("EnsureSet applied definitions that failed parser validation")
	}
}

func TestEnsureSetAppliesBothSupportedFamiliesAfterValidation(t *testing.T) {
	restoreNft := stubNft(t, nil, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" {
			return errors.New("table missing")
		}
		t.Fatalf("unexpected nft query: %#v", args)
		return nil
	})
	defer restoreNft()
	var checked, applied string
	restoreApply := stubNftScript(t, func(script string) error {
		applied = script
		return nil
	})
	defer restoreApply()
	restoreCheck := stubNftScriptCheck(t, func(script string) error {
		checked = script
		return nil
	})
	defer restoreCheck()

	if err := New("serpent_wrt", "blocked_ips", time.Hour).EnsureSet(); err != nil {
		t.Fatalf("EnsureSet: %v", err)
	}
	if checked == "" || checked != applied {
		t.Fatalf("apply script was not the validated batch: checked=%q applied=%q", checked, applied)
	}
	if !strings.Contains(applied, "blocked_ips_v4 { type ipv4_addr;") ||
		!strings.Contains(applied, "blocked_ips_v6 { type ipv6_addr;") {
		t.Fatalf("dual-stack set definitions missing: %s", applied)
	}
}

func TestValidateSetDefinitionsOnlyChecksTheBatch(t *testing.T) {
	restoreNft := stubNft(t, nil, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" {
			return errors.New("validation table absent")
		}
		t.Fatalf("unexpected nft command: %#v", args)
		return nil
	})
	defer restoreNft()
	var checked string
	restoreCheck := stubNftScriptCheck(t, func(script string) error {
		checked = script
		return nil
	})
	defer restoreCheck()
	applied := false
	restoreApply := stubNftScript(t, func(string) error {
		applied = true
		return nil
	})
	defer restoreApply()

	if err := New("serpent_wrt", "blocked_ips", time.Hour).ValidateSetDefinitions(); err != nil {
		t.Fatalf("ValidateSetDefinitions: %v", err)
	}
	if !strings.Contains(checked, "type ipv4_addr") || !strings.Contains(checked, "type ipv6_addr") {
		t.Fatalf("validation batch omitted an address family: %s", checked)
	}
	if applied {
		t.Fatal("parser validation applied a ruleset")
	}
}

func TestEnsureSetIsNoopWhenBothFamiliesExist(t *testing.T) {
	restoreNft := stubNft(t, nil, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" && (len(args) < 4 || args[3] != "serpent_wrt") {
			return errors.New("validation table absent")
		}
		return nil
	})
	defer restoreNft()
	checked := false
	restoreCheck := stubNftScriptCheck(t, func(string) error {
		checked = true
		return nil
	})
	defer restoreCheck()
	applied := false
	restoreApply := stubNftScript(t, func(string) error {
		applied = true
		return nil
	})
	defer restoreApply()

	if err := New("serpent_wrt", "blocked_ips", time.Hour).EnsureSet(); err != nil {
		t.Fatalf("EnsureSet: %v", err)
	}
	if !checked || applied {
		t.Fatalf("existing sets should validate without apply: checked=%t applied=%t", checked, applied)
	}
}

func TestEnsureSetAddsOnlyMissingAddressFamily(t *testing.T) {
	restoreNft := stubNft(t, nil, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" && (len(args) < 4 || args[3] != "serpent_wrt") {
			return errors.New("validation table absent")
		}
		if len(args) > 1 && args[1] == "table" {
			return nil
		}
		if len(args) > 4 && args[4] == "blocked_ips_v6" {
			return errors.New("IPv6 set missing")
		}
		return nil
	})
	defer restoreNft()
	var checked, applied string
	restoreCheck := stubNftScriptCheck(t, func(script string) error {
		checked = script
		return nil
	})
	defer restoreCheck()
	restoreApply := stubNftScript(t, func(script string) error {
		applied = script
		return nil
	})
	defer restoreApply()

	if err := New("serpent_wrt", "blocked_ips", time.Hour).EnsureSet(); err != nil {
		t.Fatalf("EnsureSet: %v", err)
	}
	if checked == "" || checked != applied ||
		!strings.Contains(applied, "blocked_ips_v6") ||
		strings.Contains(applied, "blocked_ips_v4") ||
		strings.Contains(applied, "add table") {
		t.Fatalf("partial repair batch is wrong: %q", applied)
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

	check := New("serpent_wrt", "blocked_ips", time.Hour).Check()
	if !check.Available || !check.TablePresent || !check.SetPresent ||
		!check.IPv4SetPresent || !check.IPv6SetPresent || check.Error != "" {
		t.Fatalf("check: got %+v, want both address-family sets ready", check)
	}
	if len(calls) != 3 {
		t.Fatalf("nft calls: got %d, want table and two set checks", len(calls))
	}
	if calls[1][4] != "blocked_ips_v4" || calls[2][4] != "blocked_ips_v6" {
		t.Fatalf("set checks: got %#v", calls)
	}
}

func TestCheckMissingIPv6SetReportsPartialState(t *testing.T) {
	restore := stubNft(t, nil, func(args ...string) error {
		if len(args) > 4 && args[4] == "blocked_ips_v6" {
			return errors.New("IPv6 set missing")
		}
		return nil
	})
	defer restore()

	check := New("serpent_wrt", "blocked_ips", time.Hour).Check()
	if !check.Available || !check.TablePresent || check.SetPresent ||
		!check.IPv4SetPresent || check.IPv6SetPresent {
		t.Fatalf("check: got %+v, want IPv4 present and IPv6 missing", check)
	}
	if !strings.Contains(check.Error, "IPv6 set missing") {
		t.Fatalf("error: got %q, want IPv6 set diagnostic", check.Error)
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

	check := New("serpent_wrt", "blocked_ips", time.Hour).Check()
	if !check.Available || !check.TablePresent || check.SetPresent ||
		check.IPv4SetPresent || check.IPv6SetPresent {
		t.Fatalf("check: got %+v, want missing sets", check)
	}
	if !strings.Contains(check.Error, "set missing") {
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

func TestListBlockedCombinesAddressFamilies(t *testing.T) {
	restore := stubNftListSet(t, func(table, set string) ([]string, error) {
		if table != "serpent_wrt" {
			t.Fatalf("table: got %q, want serpent_wrt", table)
		}
		switch set {
		case "blocked_ips_v4":
			return []string{"192.0.2.1"}, nil
		case "blocked_ips_v6":
			return []string{"2001:db8::1"}, nil
		default:
			t.Fatalf("unexpected nft set %q", set)
			return nil, nil
		}
	})
	defer restore()

	blocked, err := New("serpent_wrt", "blocked_ips", time.Hour).ListBlocked()
	if err != nil {
		t.Fatalf("ListBlocked: %v", err)
	}
	if len(blocked) != 2 || blocked[0] != "192.0.2.1" || blocked[1] != "2001:db8::1" {
		t.Fatalf("blocked entries: got %#v", blocked)
	}
}

func TestListBlockedReportsPartialSetFailure(t *testing.T) {
	restore := stubNftListSet(t, func(_, set string) ([]string, error) {
		if set == "blocked_ips_v6" {
			return nil, errors.New("IPv6 set missing")
		}
		return []string{"192.0.2.1"}, nil
	})
	defer restore()

	if _, err := New("serpent_wrt", "blocked_ips", time.Hour).ListBlocked(); err == nil ||
		!strings.Contains(err.Error(), "IPv6 set missing") {
		t.Fatalf("ListBlocked error: got %v, want IPv6 set error", err)
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

func stubNftListSet(t *testing.T, runner func(table, set string) ([]string, error)) func() {
	t.Helper()
	oldRunNftListSet := runNftListSet
	runNftListSet = runner
	return func() {
		runNftListSet = oldRunNftListSet
	}
}

func stubNftScriptCheck(t *testing.T, runner func(string) error) func() {
	t.Helper()
	oldRunNftScriptCheck := runNftScriptCheck
	runNftScriptCheck = runner
	return func() {
		runNftScriptCheck = oldRunNftScriptCheck
	}
}
