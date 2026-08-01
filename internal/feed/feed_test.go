package feed_test

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ecan0/serpent-wrt/internal/feed"
)

func TestFeedLoadAndContains(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load: %v", err)
	}

	// exact IP in feed
	if !f.Contains(net.ParseIP("1.2.3.4")) {
		t.Error("expected 1.2.3.4 to be in feed")
	}

	// IP inside a CIDR in feed (5.6.7.0/24)
	if !f.Contains(net.ParseIP("5.6.7.100")) {
		t.Error("expected 5.6.7.100 to match CIDR 5.6.7.0/24")
	}

	// IP not in feed
	if f.Contains(net.ParseIP("9.9.9.9")) {
		t.Error("expected 9.9.9.9 to not be in feed")
	}
}

func TestFeedLen(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Len() == 0 {
		t.Error("expected non-empty feed after load")
	}
}

func TestFeedReload(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("first load: %v", err)
	}
	before := f.Len()

	// reload same file — should succeed and produce same count
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if f.Len() != before {
		t.Errorf("len changed after reload: %d → %d", before, f.Len())
	}
}

func TestFeedLoadRejectsMalformedEntries(t *testing.T) {
	path := writeFeed(t, `
# comment

1.2.3.4
not-an-ip
5.6.7.0/24
`)
	f := feed.New()
	err := f.Load(path)
	if err == nil {
		t.Fatal("expected malformed feed load to fail")
	}
	if !strings.Contains(err.Error(), "line 5") || !strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("error: got %q, want line and entry context", err)
	}
	if f.Len() != 0 {
		t.Fatalf("failed load changed feed: got %d entries, want 0", f.Len())
	}
}

func TestFeedLoadAcceptsIPv6(t *testing.T) {
	path := writeFeed(t, `
2001:db8::/32
2001:db8::1
1.2.3.4
`)
	f := feed.New()
	if err := f.Load(path); err != nil {
		t.Fatalf("load IPv6 feed: %v", err)
	}
	if !f.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("expected IPv6 exact address to match")
	}
	if !f.Contains(net.ParseIP("2001:db8:1::1")) {
		t.Error("expected IPv6 CIDR to match")
	}
	if f.Len() != 3 {
		t.Fatalf("len: got %d, want 3", f.Len())
	}
}

func TestFeedLoadDeduplicatesExactIPs(t *testing.T) {
	path := writeFeed(t, `
1.2.3.4
1.2.3.4
5.6.7.0/24
`)
	f := feed.New()
	if err := f.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Len() != 2 {
		t.Fatalf("len: got %d, want 2", f.Len())
	}
}

func TestFeedFailedReloadKeepsPreviousEntries(t *testing.T) {
	path := writeFeed(t, `
1.2.3.4
5.6.7.0/24
`)
	f := feed.New()
	if err := f.Load(path); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	before := f.Len()

	missingPath := filepath.Join(t.TempDir(), "missing-feed.txt")
	if err := f.Load(missingPath); err == nil {
		t.Fatal("expected missing feed reload to fail")
	}
	if f.Len() != before {
		t.Fatalf("len after failed reload: got %d, want %d", f.Len(), before)
	}
	if !f.Contains(net.ParseIP("1.2.3.4")) {
		t.Error("previous exact IP entry should survive failed reload")
	}
	if !f.Contains(net.ParseIP("5.6.7.100")) {
		t.Error("previous CIDR entry should survive failed reload")
	}
}

func TestFeedSupportsIPv6(t *testing.T) {
	f := feed.New()
	path := writeFeed(t, "2001:db8::/32\n")
	if err := f.Load(path); err != nil {
		t.Fatalf("load IPv6 feed: %v", err)
	}
	if !f.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("IPv6 address should match")
	}
}

func TestValidateFileSuccess(t *testing.T) {
	path := writeFeed(t, `
# comment
1.2.3.4
5.6.7.0/24
`)
	count, err := feed.ValidateFile(path)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if count != 2 {
		t.Fatalf("count: got %d, want 2", count)
	}
}

func TestValidateFileRejectsMalformedEntry(t *testing.T) {
	path := writeFeed(t, `
1.2.3.4
not-an-ip
`)
	_, err := feed.ValidateFile(path)
	if err == nil {
		t.Fatal("expected malformed entry error")
	}
	if !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("error: got %q, want line and entry context", err)
	}
}

func TestValidateFileAcceptsIPv6(t *testing.T) {
	path := writeFeed(t, "::1\n2001:db8::/32\n")
	count, err := feed.ValidateFile(path)
	if err != nil {
		t.Fatalf("validate IPv6 feed: %v", err)
	}
	if count != 2 {
		t.Fatalf("count: got %d, want 2", count)
	}
}

func writeFeed(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
