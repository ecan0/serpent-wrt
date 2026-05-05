package feed_test

import (
	"net"
	"os"
	"path/filepath"
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

func TestFeedLoadIgnoresCommentsBlankAndMalformedEntries(t *testing.T) {
	path := writeFeed(t, `
# comment

1.2.3.4
not-an-ip
300.300.300.300
5.6.7.0/24
bad/cidr
::1
`)
	f := feed.New()
	if err := f.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if f.Len() != 2 {
		t.Fatalf("len: got %d, want 2", f.Len())
	}
	if !f.Contains(net.ParseIP("1.2.3.4")) {
		t.Error("expected exact IPv4 entry to match")
	}
	if !f.Contains(net.ParseIP("5.6.7.100")) {
		t.Error("expected IPv4 CIDR entry to match")
	}
	if f.Contains(net.ParseIP("9.9.9.9")) {
		t.Error("unexpected match for absent IPv4")
	}
	if f.Contains(net.ParseIP("::1")) {
		t.Error("IPv6 entries should be ignored")
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

func TestFeedIPv4Only(t *testing.T) {
	f := feed.New()
	if err := f.Load("../../testdata/threat-feed.txt"); err != nil {
		t.Fatalf("load: %v", err)
	}
	// IPv6 addresses should never match
	if f.Contains(net.ParseIP("::1")) {
		t.Error("IPv6 loopback should not match feed")
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
