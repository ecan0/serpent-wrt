package feed

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Feed holds parsed threat intel entries and supports safe concurrent reload.
// Entries are either exact IPv4 addresses or CIDRs.
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

// Load parses the threat feed file and atomically replaces the current entries.
func (f *Feed) Load(path string) error {
	ips, cidrs, err := parseFile(path)
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
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	key := ip4.String()
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, ok := f.ips[key]; ok {
		return true
	}
	for _, cidr := range f.cidrs {
		if cidr.Contains(ip4) {
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

func parseFile(path string) (map[string]struct{}, []*net.IPNet, error) {
	return parseFileMode(path, false)
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
					return nil, nil, fmt.Errorf("line %d: invalid IPv4 CIDR %q: %w", lineNo, line, err)
				}
				continue // skip malformed entries
			}
			if ip.To4() == nil {
				if strict {
					return nil, nil, fmt.Errorf("line %d: IPv6 CIDR is not supported: %q", lineNo, line)
				}
				continue
			}
			cidrs = append(cidrs, ipnet)
		} else {
			ip := net.ParseIP(line)
			if ip == nil || ip.To4() == nil {
				if strict {
					return nil, nil, fmt.Errorf("line %d: invalid IPv4 address %q", lineNo, line)
				}
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ips[ip4.String()] = struct{}{}
			}
		}
	}
	return ips, cidrs, scanner.Err()
}
