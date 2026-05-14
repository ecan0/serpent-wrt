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

var (
	lookPath      = exec.LookPath
	runNftCommand = runNftCheck
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

// NftCheck reports whether the configured nftables resources are visible.
type NftCheck struct {
	Available    bool
	TablePresent bool
	SetPresent   bool
	Error        string
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
	_, err := lookPath("nft")
	return err == nil
}

// Check returns a cheap status snapshot for the configured nftables resources.
func (e *Enforcer) Check() NftCheck {
	if !e.Available() {
		return NftCheck{
			Available: false,
			Error:     "nft not found in PATH",
		}
	}

	if err := runNftCommand("list", "table", "inet", e.table); err != nil {
		return NftCheck{
			Available: true,
			Error:     err.Error(),
		}
	}
	if err := runNftCommand("list", "set", "inet", e.table, e.set); err != nil {
		return NftCheck{
			Available:    true,
			TablePresent: true,
			Error:        err.Error(),
		}
	}
	return NftCheck{
		Available:    true,
		TablePresent: true,
		SetPresent:   true,
	}
}

// EnsureSet creates the nftables table and set if they do not already exist.
// Uses nft -f - so the entire script is parsed atomically.
func (e *Enforcer) EnsureSet() error {
	return e.runScript(ensureSetScript(e.table, e.set))
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

	return e.runScript(blockScript(e.table, e.set, key, e.duration))
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

func runNftCheck(args ...string) error {
	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureSetScript(table, set string) string {
	return fmt.Sprintf(
		"add table inet %s\nadd set inet %s %s { type ipv4_addr; flags timeout; }\n",
		table, table, set,
	)
}

func blockScript(table, set, ip string, duration time.Duration) string {
	return fmt.Sprintf(
		"add element inet %s %s { %s timeout %s }\n",
		table, set, ip, formatDuration(duration),
	)
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
