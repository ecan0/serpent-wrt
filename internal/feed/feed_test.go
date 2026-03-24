package feed_test

import (
	"net"
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
