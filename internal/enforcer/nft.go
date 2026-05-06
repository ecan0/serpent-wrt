// Package enforcer manages nftables blocking via the nft CLI.
package enforcer

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Enforcer manages a named nftables inet set for dynamically blocked IPs.
// It is idempotent: blocking an already-blocked IP is a no-op.
type Enforcer struct {
	table    string
	set      string
	duration time.Duration

	mu      sync.Mutex
	blocked map[string]time.Time // ip string → unblock time
}

// New creates an Enforcer targeting the given nftables table and set.
func New(table, set string, duration time.Duration) *Enforcer {
	return &Enforcer{
		table:    table,
		set:      set,
		duration: duration,
		blocked:  make(map[string]time.Time),
	}
}

// Available reports whether the nft CLI is present in PATH.
func (e *Enforcer) Available() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// EnsureSet creates the nftables table and set if they do not already exist.
// Uses nft -f - so the entire script is parsed atomically.
func (e *Enforcer) EnsureSet() error {
	script := fmt.Sprintf(
		"add table inet %s\nadd set inet %s %s { type ipv4_addr; flags timeout; }\n",
		e.table, e.table, e.set,
	)
	return e.runScript(script)
}

// Block adds ip to the nftables blocked set with a timeout.
// If ip is already tracked as blocked, the call is a no-op.
func (e *Enforcer) Block(ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil // IPv6 not supported in MVP
	}
	key := ip4.String()

	e.mu.Lock()
	if exp, ok := e.blocked[key]; ok && time.Now().Before(exp) {
		e.mu.Unlock()
		return nil // already blocked
	}
	e.blocked[key] = time.Now().Add(e.duration)
	e.mu.Unlock()

	script := fmt.Sprintf(
		"add element inet %s %s { %s timeout %s }\n",
		e.table, e.set, key, formatDuration(e.duration),
	)
	return e.runScript(script)
}

// IsBlocked reports whether ip is currently tracked as blocked.
func (e *Enforcer) IsBlocked(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	e.mu.Lock()
	exp, ok := e.blocked[ip4.String()]
	e.mu.Unlock()
	return ok && time.Now().Before(exp)
}

// Prune removes expired entries from the internal tracking map.
// nftables handles its own timeout expiry; this just keeps our map bounded.
func (e *Enforcer) Prune() {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for ip, exp := range e.blocked {
		if now.After(exp) {
			delete(e.blocked, ip)
		}
	}
}

// ListBlocked shells out to nft to list the current contents of the blocked set.
// Returns nil (not an error) if the set does not exist.
func (e *Enforcer) ListBlocked() ([]string, error) {
	cmd := exec.Command("nft", "list", "set", "inet", e.table, e.set)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If the set doesn't exist, nft returns an error — treat as empty.
		return nil, nil
	}
	return parseSetElements(string(out)), nil
}

// parseSetElements extracts IPs from nft list set output.
// The elements line looks like: "elements = { 1.2.3.4 timeout 1h, 5.6.7.8 timeout 1h }"
func parseSetElements(output string) []string {
	var ips []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "elements") {
			continue
		}
		// Strip "elements = { ... }"
		start := strings.Index(line, "{")
		end := strings.LastIndex(line, "}")
		if start < 0 || end < 0 || end <= start {
			continue
		}
		inner := line[start+1 : end]
		for _, elem := range strings.Split(inner, ",") {
			fields := strings.Fields(strings.TrimSpace(elem))
			if len(fields) > 0 && net.ParseIP(fields[0]) != nil {
				ips = append(ips, fields[0])
			}
		}
	}
	if ips == nil {
		return []string{}
	}
	return ips
}

func (e *Enforcer) runScript(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// formatDuration produces an nft-compatible timeout string (e.g. "1h", "30m", "90s").
func formatDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
