// Package lease parses dnsmasq DHCP lease files for lightweight host
// attribution. It is read-only and intentionally ignores malformed rows.
package lease

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	DefaultPath     = "/tmp/dhcp.leases"
	DefaultRefresh  = time.Minute
	MaxLeaseEntries = 4096
)

// Entry is the host metadata dnsmasq exposes for a leased IPv4 address.
type Entry struct {
	IP       string
	MAC      string
	Hostname string
}

// Cache keeps a bounded, periodically refreshed snapshot of dnsmasq leases.
type Cache struct {
	path     string
	interval time.Duration

	mu      sync.Mutex
	last    time.Time
	entries map[string]Entry
}

// NewCache creates a lease cache. Empty paths disable lookups.
func NewCache(path string) *Cache {
	return &Cache{
		path:     path,
		interval: DefaultRefresh,
		entries:  make(map[string]Entry),
	}
}

// Lookup returns lease metadata for ip, refreshing the cache if needed.
func (c *Cache) Lookup(ip net.IP) (Entry, bool) {
	if c == nil || c.path == "" || ip == nil {
		return Entry{}, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return Entry{}, false
	}

	c.refreshIfStale(time.Now())

	c.mu.Lock()
	entry, ok := c.entries[ip4.String()]
	c.mu.Unlock()
	return entry, ok
}

func (c *Cache) refreshIfStale(now time.Time) {
	c.mu.Lock()
	if !c.last.IsZero() && now.Sub(c.last) < c.interval {
		c.mu.Unlock()
		return
	}
	c.last = now
	c.mu.Unlock()

	entries, err := LoadFile(c.path)
	if err != nil {
		return
	}

	c.mu.Lock()
	c.entries = entries
	c.mu.Unlock()
}

// LoadFile parses a dnsmasq lease file. Missing files are treated as empty.
func LoadFile(path string) (map[string]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]Entry{}, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Parse(f), nil
}

// Parse reads dnsmasq lease rows:
//
//	<expiry> <mac> <ip> <hostname> <client-id>
func Parse(r io.Reader) map[string]Entry {
	out := make(map[string]Entry)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if len(out) >= MaxLeaseEntries {
			break
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip := net.ParseIP(fields[2])
		if ip == nil || ip.To4() == nil {
			continue
		}
		mac := strings.ToLower(fields[1])
		if _, err := net.ParseMAC(mac); err != nil {
			continue
		}
		hostname := fields[3]
		if hostname == "*" {
			hostname = ""
		}
		out[ip.To4().String()] = Entry{
			IP:       ip.To4().String(),
			MAC:      mac,
			Hostname: hostname,
		}
	}
	return out
}
