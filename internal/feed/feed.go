package feed

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Feed holds parsed threat-intelligence entries and supports safe concurrent
// reload. Entries may be IPv4 or IPv6 addresses/CIDRs.
type Feed struct {
	mu    sync.RWMutex
	ips   map[string]struct{}
	cidrs []*net.IPNet
}

func New() *Feed {
	return &Feed{
		ips: make(map[string]struct{}),
	}
}

// Load strictly parses the threat feed file and atomically replaces the current
// entries. Invalid or unsupported entries fail the load so a bad update cannot
// silently weaken detection coverage.
func (f *Feed) Load(path string) error {
	ips, cidrs, err := parseFileMode(path, true)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.ips = ips
	f.cidrs = cidrs
	f.mu.Unlock()
	return nil
}

// Contains reports whether ip matches any entry in the feed.
func (f *Feed) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	key := ip.String()
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, ok := f.ips[key]; ok {
		return true
	}
	for _, cidr := range f.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Len returns the total number of entries (IPs + CIDRs).
func (f *Feed) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.ips) + len(f.cidrs)
}

// ValidateFile strictly validates a threat feed without mutating a Feed.
// Unlike Load, malformed entries are returned as errors so configtest can fail
// before the daemon starts or reloads with an unintended feed.
func ValidateFile(path string) (int, error) {
	ips, cidrs, err := parseFileMode(path, true)
	if err != nil {
		return 0, err
	}
	return len(ips) + len(cidrs), nil
}

func parseFileMode(path string, strict bool) (map[string]struct{}, []*net.IPNet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open feed %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	ips := make(map[string]struct{})
	var cidrs []*net.IPNet

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			ip, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				if strict {
					return nil, nil, fmt.Errorf("line %d: invalid IP CIDR %q: %w", lineNo, line, err)
				}
				continue
			}
			network := ip.Mask(ipnet.Mask)
			cidrs = append(cidrs, &net.IPNet{IP: network, Mask: ipnet.Mask})
		} else {
			ip := net.ParseIP(line)
			if ip == nil {
				if strict {
					return nil, nil, fmt.Errorf("line %d: invalid IP address %q", lineNo, line)
				}
				continue
			}
			ips[ip.String()] = struct{}{}
		}
	}
	return ips, cidrs, scanner.Err()
}
