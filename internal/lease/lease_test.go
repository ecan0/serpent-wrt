package lease

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDnsmasqLeases(t *testing.T) {
	input := strings.NewReader(`
1710000000 AA:BB:CC:DD:EE:FF 192.168.1.20 laptop 01:aa:bb
1710000001 11:22:33:44:55:66 192.168.1.21 * *
not enough fields
1710000002 bad-mac 192.168.1.22 ignored *
1710000003 aa:bb:cc:dd:ee:11 not-an-ip ignored *
`)
	entries := Parse(input)
	if len(entries) != 2 {
		t.Fatalf("entries: got %d, want 2 (%#v)", len(entries), entries)
	}
	laptop := entries["192.168.1.20"]
	if laptop.MAC != "aa:bb:cc:dd:ee:ff" || laptop.Hostname != "laptop" {
		t.Fatalf("laptop entry: got %+v", laptop)
	}
	anon := entries["192.168.1.21"]
	if anon.MAC != "11:22:33:44:55:66" || anon.Hostname != "" {
		t.Fatalf("anonymous entry: got %+v", anon)
	}
}

func TestLoadFileMissingIsEmpty(t *testing.T) {
	entries, err := LoadFile(filepath.Join(t.TempDir(), "missing.leases"))
	if err != nil {
		t.Fatalf("load missing file: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries: got %d, want 0", len(entries))
	}
}

func TestCacheLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.leases")
	if err := os.WriteFile(path, []byte("1710000000 aa:bb:cc:dd:ee:ff 192.168.1.20 laptop *\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cache := NewCache(path)
	entry, ok := cache.Lookup(net.ParseIP("192.168.1.20"))
	if !ok {
		t.Fatal("expected lease lookup hit")
	}
	if entry.Hostname != "laptop" || entry.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("entry: got %+v", entry)
	}
	if _, ok := cache.Lookup(net.ParseIP("192.168.1.99")); ok {
		t.Fatal("unexpected lease lookup hit")
	}

	stats := cache.Stats()
	if stats.Path != path {
		t.Fatalf("stats path: got %q, want %q", stats.Path, path)
	}
	if stats.Entries != 1 {
		t.Fatalf("stats entries: got %d, want 1", stats.Entries)
	}
	if stats.LastRefresh.IsZero() {
		t.Fatal("stats last refresh should be set after lookup")
	}
	if stats.LastError != "" {
		t.Fatalf("stats last error: got %q, want empty", stats.LastError)
	}
}

func TestCacheLookupSkipsIPv6(t *testing.T) {
	cache := NewCache("/tmp/does-not-matter")
	if _, ok := cache.Lookup(net.ParseIP("2001:db8::1")); ok {
		t.Fatal("IPv6 lookup should miss")
	}
}

func TestCacheStatsRecordsLoadError(t *testing.T) {
	cache := NewCache("bad\x00path")
	if _, ok := cache.Lookup(net.ParseIP("192.168.1.20")); ok {
		t.Fatal("invalid path should not produce lease hit")
	}
	stats := cache.Stats()
	if stats.LastError == "" {
		t.Fatal("stats last error should be set")
	}
	if stats.Entries != 0 {
		t.Fatalf("stats entries: got %d, want 0", stats.Entries)
	}
}
