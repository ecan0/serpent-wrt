// Package enforcer manages nftables blocking via the nft CLI.
package enforcer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	lookPath          = exec.LookPath
	runNftCommand     = runNftCheck
	runNftScript      = runNftScriptCommand
	runNftScriptCheck = runNftScriptCheckCommand
	runNftListSet     = listNftSetCommand
	runNftJSON        = runNftJSONCommand
)

// Enforcer manages IPv4 and IPv6 nftables sets with kernel timeouts.
// It is idempotent: blocking an already-blocked IP is a no-op.
type Enforcer struct {
	table    string
	set      string
	duration time.Duration

	mu                 sync.Mutex
	blocked            map[string]time.Time // ip string → unblock time
	resourcesRecreated bool
}

// NftCheck reports whether both family-specific sets are visible.
type NftCheck struct {
	Available      bool
	TablePresent   bool
	SetPresent     bool
	IPv4SetPresent bool
	IPv6SetPresent bool
	Error          string
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

	check := NftCheck{Available: true, TablePresent: true}
	v4Err := runNftCommand("list", "set", "inet", e.table, familySetName(e.set, true))
	v6Err := runNftCommand("list", "set", "inet", e.table, familySetName(e.set, false))
	check.IPv4SetPresent = v4Err == nil
	check.IPv6SetPresent = v6Err == nil
	check.SetPresent = check.IPv4SetPresent && check.IPv6SetPresent
	switch {
	case v4Err != nil && v6Err != nil:
		check.Error = fmt.Sprintf("IPv4 set: %v; IPv6 set: %v", v4Err, v6Err)
	case v4Err != nil:
		check.Error = fmt.Sprintf("IPv4 set: %v", v4Err)
	case v6Err != nil:
		check.Error = fmt.Sprintf("IPv6 set: %v", v6Err)
	}
	return check
}

// EnsureSet validates and creates the IPv4 and IPv6 sets when they are
// missing. It preserves the historical caller contract; EnsureResources
// additionally reports whether resources had to be recreated.
func (e *Enforcer) EnsureSet() error {
	_, err := e.EnsureResources()
	return err
}

// EnsureResources validates and creates the table and timed sets when they are
// missing, preserving existing sets and their elements. recreated reports that
// kernel resources had to be restored.
func (e *Enforcer) EnsureResources() (bool, error) {
	var recreated bool
	err := withFirewallLock(func() error {
		var innerErr error
		recreated, innerErr = e.ensureResourcesLocked()
		return innerErr
	})
	return recreated, err
}

func (e *Enforcer) ensureResourcesLocked() (bool, error) {
	if err := e.ValidateSetDefinitions(); err != nil {
		return false, fmt.Errorf("nftables set validation failed: %w", err)
	}
	check := e.Check()
	if !check.Available {
		return false, fmt.Errorf("cannot validate nftables sets: %s", check.Error)
	}
	if check.TablePresent && check.SetPresent {
		return false, nil
	}
	e.mu.Lock()
	if !check.TablePresent {
		clear(e.blocked)
	} else {
		for address := range e.blocked {
			isIPv4 := net.ParseIP(address).To4() != nil
			if (isIPv4 && !check.IPv4SetPresent) || (!isIPv4 && !check.IPv6SetPresent) {
				delete(e.blocked, address)
			}
		}
	}
	e.mu.Unlock()
	script := ensureSetScript(
		e.table,
		e.set,
		!check.TablePresent,
		!check.IPv4SetPresent,
		!check.IPv6SetPresent,
	)
	if err := runNftScriptCheck(script); err != nil {
		return false, fmt.Errorf("nftables set validation failed: %w", err)
	}
	if err := e.runScript(script); err != nil {
		return false, err
	}
	e.mu.Lock()
	e.resourcesRecreated = true
	e.mu.Unlock()
	return true, nil
}

// ValidateSetDefinitions parses the dual-stack set batch without applying it.
func (e *Enforcer) ValidateSetDefinitions() error {
	var table string
	for attempt := range 4 {
		candidate := fmt.Sprintf("serpent_wrt_validate_%d_%d", os.Getpid(), time.Now().UnixNano()+int64(attempt))
		if runNftCommand("list", "table", "inet", candidate) != nil {
			table = candidate
			break
		}
	}
	if table == "" {
		return fmt.Errorf("cannot find an unused nft validation table name")
	}
	script := ensureSetScript(table, e.set, true, true, true)
	if err := runNftScriptCheck(script); err != nil {
		return fmt.Errorf("validate nftables set definitions: %w", err)
	}
	return nil
}

// Block adds ip to the nftables set for its address family with a timeout.
func (e *Enforcer) Block(ip net.IP) error {
	if ip == nil {
		return nil
	}
	key := ip.String()
	setName := familySetName(e.set, ip.To4() != nil)

	e.mu.Lock()
	exp, ok := e.blocked[key]
	e.mu.Unlock()
	if ok && time.Now().Before(exp) {
		present, err := e.kernelElementPresent(setName, key)
		if err != nil {
			// A firewall reload can remove the sets while the cache is intact.
			if _, ensureErr := e.EnsureResources(); ensureErr != nil {
				return fmt.Errorf("restore nftables set %s before verifying %s: %w", setName, key, ensureErr)
			}
			present, err = e.kernelElementPresent(setName, key)
			if err != nil {
				return fmt.Errorf("verify %s in nftables set %s: %w", key, setName, err)
			}
		}
		if present {
			return nil
		}
		e.mu.Lock()
		delete(e.blocked, key)
		e.mu.Unlock()
	}

	return withFirewallLock(func() error {
		if err := e.runScript(blockScript(e.table, setName, key, e.duration)); err != nil {
			return err
		}
		e.mu.Lock()
		e.blocked[key] = time.Now().Add(e.duration)
		e.mu.Unlock()
		return nil
	})
}

// IsBlocked reports whether ip is currently tracked as blocked.
func (e *Enforcer) IsBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	e.mu.Lock()
	exp, ok := e.blocked[ip.String()]
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

// ListBlocked returns entries from both address-family sets.
// It preserves the historical empty result when neither set exists.
func (e *Enforcer) ListBlocked() ([]string, error) {
	v4, err4 := runNftListSet(e.table, familySetName(e.set, true))
	v6, err6 := runNftListSet(e.table, familySetName(e.set, false))
	if err4 != nil && err6 != nil {
		return nil, nil
	}
	if err4 != nil {
		return nil, fmt.Errorf("list IPv4 blocked set: %w", err4)
	}
	if err6 != nil {
		return nil, fmt.Errorf("list IPv6 blocked set: %w", err6)
	}
	return append(v4, v6...), nil
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

func listNftSetCommand(table, set string) ([]string, error) {
	cmd := exec.Command("nft", "list", "set", "inet", table, set)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft list set inet %s %s: %w (output: %s)", table, set, err, strings.TrimSpace(string(out)))
	}
	return parseSetElements(string(out)), nil
}

func (e *Enforcer) runScript(script string) error {
	return runNftScript(script)
}

func runNftScriptCommand(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runNftScriptCheckCommand(script string) error {
	cmd := exec.Command("nft", "--check", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft --check: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runNftJSONCommand(args ...string) ([]byte, error) {
	cmdArgs := append([]string{"-j"}, args...)
	cmd := exec.Command("nft", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nft -j %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (e *Enforcer) kernelElementPresent(set, ip string) (bool, error) {
	elements, err := runNftListSet(e.table, set)
	if err != nil {
		return false, err
	}
	for _, element := range elements {
		if element == ip {
			return true, nil
		}
	}
	return false, nil
}

func runNftCheck(args ...string) error {
	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureSetScript(table, set string, createTable, createIPv4, createIPv6 bool) string {
	var script strings.Builder
	if createTable {
		fmt.Fprintf(&script, "add table inet %s\n", table)
	}
	if createIPv4 {
		fmt.Fprintf(&script, "add set inet %s %s { type ipv4_addr; flags timeout; }\n", table, familySetName(set, true))
	}
	if createIPv6 {
		fmt.Fprintf(&script, "add set inet %s %s { type ipv6_addr; flags timeout; }\n", table, familySetName(set, false))
	}
	return script.String()
}

func familySetName(set string, ipv4 bool) string {
	if ipv4 {
		return set + "_v4"
	}
	return set + "_v6"
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
