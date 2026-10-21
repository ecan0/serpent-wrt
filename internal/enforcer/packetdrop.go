package enforcer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	// PacketDropChain is the single owned base chain used for the explicit
	// forward source-address drop policy.
	PacketDropChain = "serpent_forward"

	// PacketDropStateDisabled, PacketDropStateReady, and PacketDropStateFailed
	// are the operator-visible policy states.
	PacketDropStateDisabled = "disabled"
	PacketDropStateReady    = "ready"
	PacketDropStateFailed   = "failed"

	packetDropChainComment  = "serpent-wrt packet drop"
	packetDropStateFileName = "packet_drop_state.json"
	firewallLockFileName    = "firewall.lock"
)

var (
	runtimeStateDir = "/var/run/serpent-wrt"
	fw4IncludePath  = "/usr/share/serpent-wrt/fw4-reload"

	runUCIOutput = runUCIOutputCommand
)

func runUCIOutputCommand(args ...string) (string, error) {
	cmd := exec.Command("uci", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("uci %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// PacketDropStatus is the operator-visible state of the explicit packet-drop
// policy. Set writes and packet counters are tracked separately by callers.
type PacketDropStatus struct {
	Enabled       bool   `json:"packet_drop_enabled"`
	State         string `json:"packet_drop_state"`
	Error         string `json:"packet_drop_error"`
	ResourcesLost bool   `json:"-"`
}

// reservedTables are names owned by fw4, legacy fw3, or nftables itself. The
// managed packet-drop path requires a dedicated table.
var reservedTables = map[string]bool{
	"fw4":      true,
	"fw3":      true,
	"filter":   true,
	"nat":      true,
	"mangle":   true,
	"raw":      true,
	"security": true,
	"broute":   true,
	"inet":     true,
	"ip":       true,
	"ip6":      true,
	"arp":      true,
	"bridge":   true,
	"netdev":   true,
}

var managedIdentifierRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidatePacketDropPrerequisites verifies the fw4 and resource prerequisites
// for enabling source-address drops. It never mutates firewall state.
func ValidatePacketDropPrerequisites(table, set string) error {
	if err := validateManagedIdentifier("nft_table", table); err != nil {
		return err
	}
	if err := validateManagedIdentifier("nft_set", set); err != nil {
		return err
	}
	if len(set) > 252 {
		return fmt.Errorf("nft_set must be 252 bytes or fewer to allow the family suffix")
	}
	if reservedTables[strings.ToLower(table)] {
		return fmt.Errorf("nft_table %q is reserved or shared; packet drop requires a dedicated table", table)
	}
	if _, err := lookPath("fw4"); err != nil {
		return fmt.Errorf("fw4 is unavailable: %w", err)
	}
	if _, err := lookPath("uci"); err != nil {
		return fmt.Errorf("uci is unavailable: %w", err)
	}
	if out, err := runUCIOutput("-q", "show", "firewall"); err != nil {
		return fmt.Errorf("read fw4 configuration through uci: %w (output: %s)", err, strings.TrimSpace(out))
	}
	if err := validateNoFlowOffloading(); err != nil {
		return err
	}
	if err := validateSerpentInclude(); err != nil {
		return err
	}
	info, err := os.Stat(fw4IncludePath)
	if err != nil {
		return fmt.Errorf("fw4 include %s is unavailable: %w", fw4IncludePath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("fw4 include %s is a directory, not a script", fw4IncludePath)
	}
	f, err := os.Open(fw4IncludePath)
	if err != nil {
		return fmt.Errorf("fw4 include %s is unavailable: %w", fw4IncludePath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close fw4 include %s: %w", fw4IncludePath, err)
	}
	return validateDedicatedTable(table, set)
}

func validateManagedIdentifier(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if !managedIdentifierRE.MatchString(value) {
		return fmt.Errorf("%s %q must match %s", field, value, managedIdentifierRE.String())
	}
	return nil
}

// uciGet reads one fixed UCI option through the native parser. A missing
// option or section is reported as found=false; other command failures are
// returned so activation fails closed.
func uciGet(key string) (value string, found bool, err error) {
	out, cmdErr := runUCIOutput("-q", "get", key)
	if cmdErr != nil {
		separator := strings.LastIndexByte(key, '.')
		if separator < 0 {
			return "", false, cmdErr
		}
		// UCI uses the same exit status for missing data and read failures.
		// Prove absence through the native parent-section listing.
		parent, listErr := runUCIOutput("-q", "show", key[:separator])
		if listErr != nil {
			return "", false, fmt.Errorf("read UCI option %s: %w", key, cmdErr)
		}
		suffix := key[separator:]
		for line := range strings.SplitSeq(parent, "\n") {
			name, _, ok := strings.Cut(line, "=")
			if ok && strings.HasSuffix(name, suffix) {
				return "", false, fmt.Errorf("read present UCI option %s: %w", key, cmdErr)
			}
		}
		return "", false, nil
	}
	return strings.TrimSpace(out), true, nil
}

// uciBool applies OpenWrt UCI boolean semantics. Unknown values fail closed.
func uciBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "no", "false", "off", "disabled", "disable":
		return false, nil
	case "1", "yes", "true", "on", "enabled", "enable":
		return true, nil
	default:
		return false, fmt.Errorf("invalid UCI boolean value %q", value)
	}
}

func validateNoFlowOffloading() error {
	for _, key := range []string{
		"firewall.@defaults[0].flow_offloading",
		"firewall.@defaults[0].flow_offloading_hw",
	} {
		value, found, err := uciGet(key)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		enabled, err := uciBool(value)
		if err != nil {
			return fmt.Errorf("fw4 %s: %w", key, err)
		}
		if enabled {
			return fmt.Errorf("fw4 %s is enabled; packet drop requires software and hardware flow offloading disabled", key)
		}
	}
	return nil
}

func validateSerpentInclude() error {
	sectionType, found, err := uciGet("firewall.serpent_wrt")
	if err != nil {
		return err
	}
	if !found || sectionType != "include" {
		return fmt.Errorf("fw4 include section firewall.serpent_wrt is not registered for %s", fw4IncludePath)
	}
	for _, expected := range []struct {
		name string
		want string
	}{
		{"type", "script"},
		{"path", fw4IncludePath},
		{"fw4_compatible", "1"},
	} {
		value, found, err := uciGet("firewall.serpent_wrt." + expected.name)
		if err != nil {
			return err
		}
		if !found || value != expected.want {
			return fmt.Errorf("fw4 include firewall.serpent_wrt must set %s %q, got %q", expected.name, expected.want, value)
		}
	}
	value, found, err := uciGet("firewall.serpent_wrt.enabled")
	if err != nil {
		return err
	}
	if found {
		enabled, err := uciBool(value)
		if err != nil {
			return fmt.Errorf("fw4 include firewall.serpent_wrt enabled: %w", err)
		}
		if !enabled {
			return fmt.Errorf("fw4 include firewall.serpent_wrt is disabled")
		}
	}
	return nil
}

// validateDedicatedTable rejects an existing table that contains resources
// owned by another policy. It is read-only and never adopts foreign objects.
func validateDedicatedTable(table, set string) error {
	present, err := nftTablePresent(table)
	if err != nil {
		return fmt.Errorf("inspect nftables table inet %s: %w", table, err)
	}
	if !present {
		return nil
	}
	state, err := listTableJSONFor(table)
	if err != nil {
		return err
	}
	allowedSets := map[string]string{
		familySetName(set, true):  "ipv4_addr",
		familySetName(set, false): "ipv6_addr",
	}
	for name, actual := range state.sets {
		typ, ok := allowedSets[name]
		if !ok {
			return fmt.Errorf("nftables table inet %s contains foreign set %s; packet drop requires a dedicated table", table, name)
		}
		if actual.Type != typ {
			return fmt.Errorf("nftables set inet %s %s must have type %s, got %q", table, name, typ, actual.Type)
		}
		if !setUsesTimeout(actual) {
			return fmt.Errorf("nftables set inet %s %s must use timeout semantics", table, name)
		}
	}
	for _, chain := range state.chains {
		if chain.Name != PacketDropChain {
			return fmt.Errorf("nftables table inet %s contains foreign chain %s; packet drop requires a dedicated table", table, chain.Name)
		}
		if chain.Comment != packetDropChainComment {
			return fmt.Errorf("nftables chain inet %s %s is not owned by serpent-wrt", table, chain.Name)
		}
	}
	if len(state.rulesByChain) > 0 {
		if len(state.chains) == 0 {
			return fmt.Errorf("nftables table inet %s contains rules without the owned chain", table)
		}
		for chainName := range state.rulesByChain {
			if chainName != PacketDropChain {
				return fmt.Errorf("nftables table inet %s contains rules for foreign chain %s", table, chainName)
			}
		}
	}
	for _, element := range state.elements {
		if _, ok := allowedSets[element.Name]; !ok {
			return fmt.Errorf("nftables table inet %s contains elements for foreign set %s", table, element.Name)
		}
	}
	if len(state.foreign) > 0 {
		return fmt.Errorf("nftables table inet %s contains foreign %s resources; packet drop requires a dedicated table", table, strings.Join(state.foreign, ", "))
	}
	return nil
}

// packetDropIdentity persists the active managed resources so disable can run
// without loading a possibly broken configuration.
type packetDropIdentity struct {
	Table string `json:"table"`
	Set   string `json:"set"`
	Chain string `json:"chain"`
}

func packetDropStatePath() string {
	return filepath.Join(runtimeStateDir, packetDropStateFileName)
}

func firewallLockPath() string {
	return filepath.Join(runtimeStateDir, firewallLockFileName)
}

// ensureRuntimeStateDir creates or validates the private runtime directory.
func ensureRuntimeStateDir() (string, error) {
	if runtimeStateDir == "" {
		return "", errors.New("runtime state directory is not configured")
	}
	info, err := os.Lstat(runtimeStateDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(runtimeStateDir, 0700); err != nil {
			return "", fmt.Errorf("create runtime state directory %s: %w", runtimeStateDir, err)
		}
		info, err = os.Lstat(runtimeStateDir)
	}
	if err != nil {
		return "", fmt.Errorf("inspect runtime state directory %s: %w", runtimeStateDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("runtime state directory %s is a symlink", runtimeStateDir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("runtime state path %s is not a directory", runtimeStateDir)
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("runtime state directory %s is group or world writable", runtimeStateDir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return "", fmt.Errorf("runtime state directory %s is not owned by the current user", runtimeStateDir)
	}
	return runtimeStateDir, nil
}

// withFirewallLock serializes all managed firewall mutations behind one
// private lock file.
func withFirewallLock(fn func() error) error {
	unlock, err := acquireFirewallLock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func acquireFirewallLock() (func(), error) {
	dir, err := ensureRuntimeStateDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, firewallLockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open firewall lock %s: %w", path, err)
	}
	closeOnError := func(err error) (func(), error) {
		f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("inspect firewall lock %s: %w", path, err))
	}
	if !info.Mode().IsRegular() {
		return closeOnError(fmt.Errorf("firewall lock %s is not a regular file", path))
	}
	if info.Mode().Perm()&0077 != 0 {
		return closeOnError(fmt.Errorf("firewall lock %s is accessible by group or others", path))
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return closeOnError(fmt.Errorf("firewall lock %s is not owned by the current user", path))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return closeOnError(fmt.Errorf("lock firewall operations: %w", err))
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func readPacketDropIdentity() (packetDropIdentity, bool, error) {
	path := packetDropStatePath()
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return packetDropIdentity{}, false, nil
	}
	if err != nil {
		return packetDropIdentity{}, false, fmt.Errorf("open packet drop state %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return packetDropIdentity{}, false, fmt.Errorf("inspect packet drop state %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return packetDropIdentity{}, false, fmt.Errorf("packet drop state %s is not a regular file", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return packetDropIdentity{}, false, fmt.Errorf("packet drop state %s is accessible by group or others", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return packetDropIdentity{}, false, fmt.Errorf("packet drop state %s is not owned by the current user", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return packetDropIdentity{}, false, fmt.Errorf("read packet drop state %s: %w", path, err)
	}
	var identity packetDropIdentity
	if err := json.Unmarshal(data, &identity); err != nil {
		return packetDropIdentity{}, false, fmt.Errorf("parse packet drop state %s: %w", path, err)
	}
	if err := validateManagedIdentifier("state table", identity.Table); err != nil {
		return packetDropIdentity{}, false, err
	}
	if reservedTables[strings.ToLower(identity.Table)] {
		return packetDropIdentity{}, false, fmt.Errorf("packet drop state table %q is reserved or shared", identity.Table)
	}
	if err := validateManagedIdentifier("state set", identity.Set); err != nil {
		return packetDropIdentity{}, false, err
	}
	if identity.Chain != PacketDropChain {
		return packetDropIdentity{}, false, fmt.Errorf("packet drop state chain %q is not the managed chain", identity.Chain)
	}
	return identity, true, nil
}

func writePacketDropIdentity(identity packetDropIdentity) error {
	dir, err := ensureRuntimeStateDir()
	if err != nil {
		return err
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("encode packet drop state: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".packet_drop_state-*")
	if err != nil {
		return fmt.Errorf("create packet drop state: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure packet drop state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write packet drop state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync packet drop state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close packet drop state: %w", err)
	}
	if err := os.Rename(tmpPath, packetDropStatePath()); err != nil {
		return fmt.Errorf("install packet drop state: %w", err)
	}
	return nil
}

func removePacketDropIdentity() error {
	err := os.Remove(packetDropStatePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove packet drop state: %w", err)
	}
	return nil
}

// ReconcilePacketDrop serializes managed firewall operations, ensures the
// timed sets exist, and atomically installs or removes the owned drop chain.
func (e *Enforcer) ReconcilePacketDrop(enabled bool) (PacketDropStatus, error) {
	var status PacketDropStatus
	err := withFirewallLock(func() error {
		var reconcileErr error
		status, reconcileErr = e.reconcilePacketDropLocked(enabled)
		return reconcileErr
	})
	if err != nil {
		if status.State == "" {
			status = PacketDropStatus{Enabled: enabled, State: PacketDropStateFailed}
		}
		status.Error = err.Error()
		return status, err
	}
	return status, nil
}

func (e *Enforcer) reconcilePacketDropLocked(enabled bool) (PacketDropStatus, error) {
	if !enabled {
		if err := disablePacketDropLocked(); err != nil {
			return PacketDropStatus{State: PacketDropStateFailed, Error: err.Error()}, err
		}
		return PacketDropStatus{State: PacketDropStateDisabled}, nil
	}
	if err := ValidatePacketDropPrerequisites(e.table, e.set); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	identity, hasIdentity, err := readPacketDropIdentity()
	if err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	if hasIdentity && (identity.Table != e.table || identity.Set != e.set) {
		err := fmt.Errorf(
			"persisted packet drop identity is inet %s %s; refusing to migrate automatically to inet %s %s, run firewall disable first",
			identity.Table, identity.Set, e.table, e.set,
		)
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	if _, err := e.ensureResourcesLocked(); err != nil {
		err = fmt.Errorf("ensure nftables resources: %w", err)
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}

	table, err := e.listTableJSON()
	if err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	if err := validatePacketDropSets(table, e.set); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}

	chain, chainExists := table.chain(PacketDropChain)
	script := ""
	switch {
	case !chainExists:
		script = addPacketDropChainScript(e.table, e.set)
	default:
		if chain.Comment != packetDropChainComment {
			err := fmt.Errorf("refusing to replace unowned nftables chain %s %s %s", chain.Family, chain.Table, chain.Name)
			return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
		}
		if chainDefinitionMatches(chain) {
			script = flushPacketDropChainScript(e.table, e.set)
		} else {
			script = replacePacketDropChainScript(e.table, e.set)
		}
	}
	if err := runNftScriptCheck(script); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	// Persist a recovery target before the kernel changes. If this fails, the
	// previous rules stay untouched; if a later apply or verification fails,
	// the record lets disable remove an owned chain.
	if err := writePacketDropIdentity(packetDropIdentity{Table: e.table, Set: e.set, Chain: PacketDropChain}); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	if err := runNftScript(script); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	if err := e.checkPacketDropActive(); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}, err
	}
	e.mu.Lock()
	lost := hasIdentity && e.resourcesRecreated
	e.resourcesRecreated = false
	e.mu.Unlock()
	return PacketDropStatus{Enabled: true, State: PacketDropStateReady, ResourcesLost: lost}, nil
}

// CheckPacketDrop reads the active hook and both rule references without
// applying any change. It does not use set writes as packet evidence.
func (e *Enforcer) CheckPacketDrop(enabled bool) PacketDropStatus {
	if !enabled {
		identity, found, err := readPacketDropIdentity()
		if err != nil {
			return PacketDropStatus{State: PacketDropStateFailed, Error: err.Error()}
		}
		if !found {
			return PacketDropStatus{State: PacketDropStateDisabled}
		}
		present, err := nftTablePresent(identity.Table)
		if err != nil {
			return PacketDropStatus{State: PacketDropStateFailed, Error: err.Error()}
		}
		if !present {
			return PacketDropStatus{State: PacketDropStateDisabled}
		}
		table, err := listTableJSONFor(identity.Table)
		if err != nil {
			return PacketDropStatus{State: PacketDropStateFailed, Error: err.Error()}
		}
		if _, exists := table.chain(identity.Chain); exists {
			return PacketDropStatus{
				State: PacketDropStateFailed,
				Error: "packet drops are disabled but the recorded chain remains present; run firewall disable",
			}
		}
		return PacketDropStatus{State: PacketDropStateDisabled}
	}
	if err := ValidatePacketDropPrerequisites(e.table, e.set); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}
	}
	if err := e.checkPacketDropActive(); err != nil {
		return PacketDropStatus{Enabled: true, State: PacketDropStateFailed, Error: err.Error()}
	}
	return PacketDropStatus{Enabled: true, State: PacketDropStateReady}
}

func (e *Enforcer) checkPacketDropActive() error {
	table, err := e.listTableJSON()
	if err != nil {
		return err
	}
	chain, ok := table.chain(PacketDropChain)
	if !ok {
		return fmt.Errorf("nftables chain inet %s %s is missing", e.table, PacketDropChain)
	}
	if chain.Family != "inet" || chain.Table != e.table || chain.Name != PacketDropChain {
		return fmt.Errorf("nftables chain identity mismatch for %s %s", e.table, PacketDropChain)
	}
	if chain.Comment != packetDropChainComment {
		return fmt.Errorf("nftables chain %s %s is not owned by serpent-wrt", e.table, PacketDropChain)
	}
	if !chainDefinitionMatches(chain) {
		return fmt.Errorf("nftables chain %s %s is not type filter hook forward priority -1 policy accept", e.table, PacketDropChain)
	}
	rules := table.rules(PacketDropChain)
	if len(rules) != 2 {
		return fmt.Errorf("nftables chain %s %s must contain exactly 2 rules, found %d", e.table, PacketDropChain, len(rules))
	}
	v4Set := familySetName(e.set, true)
	v6Set := familySetName(e.set, false)
	v4, v6 := 0, 0
	for _, rule := range rules {
		switch {
		case ruleIsSourceDrop(rule, "ip", v4Set):
			v4++
		case ruleIsSourceDrop(rule, "ip6", v6Set):
			v6++
		default:
			return fmt.Errorf("nftables chain %s %s contains an unexpected rule", e.table, PacketDropChain)
		}
	}
	if v4 != 1 || v6 != 1 {
		return fmt.Errorf("nftables chain %s %s must reference @%s and @%s exactly once", e.table, PacketDropChain, v4Set, v6Set)
	}
	return nil
}

// DisablePacketDrop removes only the chain recorded in the private state
// file. It never loads configuration and is a no-op when nothing is recorded.
func DisablePacketDrop() error {
	return withFirewallLock(disablePacketDropLocked)
}

func disablePacketDropLocked() error {
	identity, ok, err := readPacketDropIdentity()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := removeRecordedChain(identity); err != nil {
		return err
	}
	return removePacketDropIdentity()
}

func removeRecordedChain(identity packetDropIdentity) error {
	if err := validateManagedIdentifier("state table", identity.Table); err != nil {
		return err
	}
	if reservedTables[strings.ToLower(identity.Table)] {
		return fmt.Errorf("refusing to remove packet drop chain from reserved or shared table %q", identity.Table)
	}
	present, err := nftTablePresent(identity.Table)
	if err != nil {
		return err
	}
	if !present {
		return removePacketDropIdentity()
	}
	table, err := listTableJSONFor(identity.Table)
	if err != nil {
		return err
	}
	chain, ok := table.chain(PacketDropChain)
	if !ok {
		return removePacketDropIdentity()
	}
	if chain.Family != "inet" || chain.Table != identity.Table || chain.Name != PacketDropChain {
		return fmt.Errorf("refusing to remove chain with mismatched identity in table %s", identity.Table)
	}
	if chain.Comment != packetDropChainComment {
		return fmt.Errorf("refusing to remove unowned nftables chain %s %s %s", chain.Family, chain.Table, chain.Name)
	}
	script := fmt.Sprintf("flush chain inet %s %s\ndelete chain inet %s %s\n", identity.Table, PacketDropChain, identity.Table, PacketDropChain)
	if err := runNftScriptCheck(script); err != nil {
		return err
	}
	if err := runNftScript(script); err != nil {
		return err
	}
	return nil
}

func addPacketDropChainScript(table, set string) string {
	var script strings.Builder
	fmt.Fprintf(&script, "add chain inet %s %s { type filter hook forward priority -1; policy accept; comment %q; }\n", table, PacketDropChain, packetDropChainComment)
	fmt.Fprintf(&script, "add rule inet %s %s ip saddr @%s counter drop\n", table, PacketDropChain, familySetName(set, true))
	fmt.Fprintf(&script, "add rule inet %s %s ip6 saddr @%s counter drop\n", table, PacketDropChain, familySetName(set, false))
	return script.String()
}

func flushPacketDropChainScript(table, set string) string {
	var script strings.Builder
	fmt.Fprintf(&script, "flush chain inet %s %s\n", table, PacketDropChain)
	fmt.Fprintf(&script, "add rule inet %s %s ip saddr @%s counter drop\n", table, PacketDropChain, familySetName(set, true))
	fmt.Fprintf(&script, "add rule inet %s %s ip6 saddr @%s counter drop\n", table, PacketDropChain, familySetName(set, false))
	return script.String()
}

func replacePacketDropChainScript(table, set string) string {
	var script strings.Builder
	fmt.Fprintf(&script, "flush chain inet %s %s\n", table, PacketDropChain)
	fmt.Fprintf(&script, "delete chain inet %s %s\n", table, PacketDropChain)
	script.WriteString(addPacketDropChainScript(table, set))
	return script.String()
}

// nft table JSON model. Only the fields needed for structural ownership and
// rule verification are decoded.

type nftListOutput struct {
	NFTables []json.RawMessage `json:"nftables"`
}

type nftObject struct {
	Table   *nftTableJSON   `json:"table"`
	Chain   *nftChainJSON   `json:"chain"`
	Set     *nftSetJSON     `json:"set"`
	Rule    *nftRuleJSON    `json:"rule"`
	Element *nftElementJSON `json:"element"`
}

type nftElementJSON struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
}

type nftTableJSON struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftSetJSON struct {
	Family  string   `json:"family"`
	Table   string   `json:"table"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Flags   []string `json:"flags"`
	Timeout int64    `json:"timeout"`
}

type nftChainJSON struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Hook    string `json:"hook"`
	Prio    int    `json:"prio"`
	Policy  string `json:"policy"`
	Comment string `json:"comment"`
}

type nftRuleJSON struct {
	Family string        `json:"family"`
	Table  string        `json:"table"`
	Chain  string        `json:"chain"`
	Expr   []nftExprJSON `json:"expr"`
}

type nftExprJSON struct {
	Match   *nftMatchJSON   `json:"match"`
	Counter json.RawMessage `json:"counter"`
	Drop    json.RawMessage `json:"drop"`
}

type nftMatchJSON struct {
	Op    string           `json:"op"`
	Left  nftMatchLeftJSON `json:"left"`
	Right json.RawMessage  `json:"right"`
}

type nftMatchLeftJSON struct {
	Payload *nftPayloadJSON `json:"payload"`
}

type nftPayloadJSON struct {
	Protocol string `json:"protocol"`
	Field    string `json:"field"`
}

type nftTableState struct {
	table        nftTableJSON
	chains       []nftChainJSON
	sets         map[string]nftSetJSON
	rulesByChain map[string][]nftRuleJSON
	elements     []nftElementJSON
	foreign      []string
}

func (s *nftTableState) chain(name string) (nftChainJSON, bool) {
	for _, chain := range s.chains {
		if chain.Name == name {
			return chain, true
		}
	}
	return nftChainJSON{}, false
}

func (s *nftTableState) rules(chain string) []nftRuleJSON {
	return s.rulesByChain[chain]
}

func (e *Enforcer) listTableJSON() (*nftTableState, error) {
	return listTableJSONFor(e.table)
}

func listTableJSONFor(table string) (*nftTableState, error) {
	out, err := runNftJSON("list", "table", "inet", table)
	if err != nil {
		return nil, err
	}
	var doc nftListOutput
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse nft JSON: %w", err)
	}
	state := &nftTableState{
		sets:         map[string]nftSetJSON{},
		rulesByChain: map[string][]nftRuleJSON{},
	}
	found := false
	for _, raw := range doc.NFTables {
		var kind map[string]json.RawMessage
		if err := json.Unmarshal(raw, &kind); err != nil {
			return nil, fmt.Errorf("parse nft JSON object: %w", err)
		}
		if len(kind) != 1 {
			state.foreign = append(state.foreign, "unknown")
			continue
		}
		var object nftObject
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, fmt.Errorf("parse nft JSON object: %w", err)
		}
		for key := range kind {
			switch key {
			case "metainfo":
			case "table":
				if object.Table != nil && object.Table.Family == "inet" && object.Table.Name == table {
					found = true
					state.table = *object.Table
				}
			case "chain":
				if object.Chain == nil || object.Chain.Family != "inet" || object.Chain.Table != table {
					continue
				}
				state.chains = append(state.chains, *object.Chain)
			case "set":
				if object.Set == nil || object.Set.Family != "inet" || object.Set.Table != table {
					continue
				}
				state.sets[object.Set.Name] = *object.Set
			case "rule":
				if object.Rule == nil || object.Rule.Family != "inet" || object.Rule.Table != table {
					continue
				}
				state.rulesByChain[object.Rule.Chain] = append(state.rulesByChain[object.Rule.Chain], *object.Rule)
			case "element":
				if object.Element == nil || object.Element.Family != "inet" || object.Element.Table != table {
					continue
				}
				state.elements = append(state.elements, *object.Element)
			default:
				state.foreign = append(state.foreign, key)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("nftables table inet %s is missing", table)
	}
	return state, nil
}

func nftTablePresent(table string) (bool, error) {
	out, err := runNftJSON("list", "tables")
	if err != nil {
		return false, err
	}
	var doc nftListOutput
	if err := json.Unmarshal(out, &doc); err != nil {
		return false, fmt.Errorf("parse nft tables JSON: %w", err)
	}
	for _, raw := range doc.NFTables {
		var object nftObject
		if err := json.Unmarshal(raw, &object); err != nil {
			return false, fmt.Errorf("parse nft tables JSON object: %w", err)
		}
		if object.Table != nil && object.Table.Family == "inet" && object.Table.Name == table {
			return true, nil
		}
	}
	return false, nil
}

func validatePacketDropSets(table *nftTableState, set string) error {
	for _, spec := range []struct {
		name string
		typ  string
	}{
		{familySetName(set, true), "ipv4_addr"},
		{familySetName(set, false), "ipv6_addr"},
	} {
		actual, ok := table.sets[spec.name]
		if !ok {
			return fmt.Errorf("nftables set inet %s %s is missing", table.table.Name, spec.name)
		}
		if actual.Type != spec.typ {
			return fmt.Errorf("nftables set inet %s %s must have type %s, got %q", table.table.Name, spec.name, spec.typ, actual.Type)
		}
		if !setUsesTimeout(actual) {
			return fmt.Errorf("nftables set inet %s %s must use timeout semantics", table.table.Name, spec.name)
		}
	}
	return nil
}

func setUsesTimeout(set nftSetJSON) bool {
	for _, flag := range set.Flags {
		if flag == "timeout" {
			return true
		}
	}
	return false
}

func chainDefinitionMatches(chain nftChainJSON) bool {
	return chain.Type == "filter" &&
		chain.Hook == "forward" &&
		chain.Prio == -1 &&
		chain.Policy == "accept"
}

// ruleIsSourceDrop requires one source-address match against the named set,
// one counter expression, and one drop expression, with no other terms.
func ruleIsSourceDrop(rule nftRuleJSON, protocol, set string) bool {
	matches, counters, drops := 0, 0, 0
	for _, expr := range rule.Expr {
		switch {
		case expr.Match != nil:
			matches++
			if expr.Match.Op != "==" || expr.Match.Left.Payload == nil {
				return false
			}
			if expr.Match.Left.Payload.Protocol != protocol || expr.Match.Left.Payload.Field != "saddr" {
				return false
			}
			var right string
			if err := json.Unmarshal(expr.Match.Right, &right); err != nil {
				return false
			}
			if right != "@"+set {
				return false
			}
		case expr.Counter != nil:
			counters++
		case expr.Drop != nil:
			drops++
		default:
			return false
		}
	}
	return matches == 1 && counters == 1 && drops == 1
}
