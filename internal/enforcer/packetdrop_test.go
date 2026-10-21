package enforcer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testNftTable = "serpent_wrt"
	testNftSet   = "blocked_ips"
)

func withTestStateDir(t *testing.T) {
	t.Helper()
	old := runtimeStateDir
	runtimeStateDir = t.TempDir()
	t.Cleanup(func() { runtimeStateDir = old })
}

// stubPrereqEnv installs a valid fw4 include file plus a native-uci seam.
// Tests may delete entries from the returned map or replace lookPath after
// this helper returns.
func stubPrereqEnv(t *testing.T) map[string]string {
	t.Helper()
	oldLookPath, oldUCI, oldInclude := lookPath, runUCIOutput, fw4IncludePath
	include := filepath.Join(t.TempDir(), "fw4-reload")
	if err := os.WriteFile(include, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("write include fixture: %v", err)
	}
	fw4IncludePath = include
	lookPath = func(file string) (string, error) {
		switch file {
		case "nft", "fw4", "uci":
			return "/usr/bin/" + file, nil
		default:
			return "", fmt.Errorf("unexpected lookPath(%q)", file)
		}
	}
	values := map[string]string{
		"firewall.@defaults[0].flow_offloading":    "0",
		"firewall.@defaults[0].flow_offloading_hw": "0",
		"firewall.serpent_wrt":                     "include",
		"firewall.serpent_wrt.type":                "script",
		"firewall.serpent_wrt.path":                include,
		"firewall.serpent_wrt.fw4_compatible":      "1",
	}
	runUCIOutput = func(args ...string) (string, error) {
		if len(args) != 3 || args[0] != "-q" {
			t.Fatalf("unexpected uci invocation: %#v", args)
		}
		switch args[1] {
		case "show":
			return "", nil
		case "get":
			value, ok := values[args[2]]
			if !ok {
				return "", errors.New("uci: Entry not found")
			}
			return value + "\n", nil
		default:
			t.Fatalf("unexpected uci subcommand: %#v", args)
			return "", nil
		}
	}
	t.Cleanup(func() {
		lookPath = oldLookPath
		runUCIOutput = oldUCI
		fw4IncludePath = oldInclude
	})
	return values
}

func stubNftJSON(t *testing.T, runner func(args ...string) ([]byte, error)) {
	t.Helper()
	old := runNftJSON
	runNftJSON = runner
	t.Cleanup(func() { runNftJSON = old })
}

func stubNftCommand(t *testing.T, runner func(args ...string) error) {
	t.Helper()
	old, oldLookPath := runNftCommand, lookPath
	runNftCommand = runner
	lookPath = func(file string) (string, error) {
		if file == "nft" {
			return "/usr/sbin/nft", nil
		}
		return oldLookPath(file)
	}
	t.Cleanup(func() {
		runNftCommand, lookPath = old, oldLookPath
	})
}

func stubScripts(t *testing.T, apply func(string) error) (checked, applied *[]string) {
	t.Helper()
	checkedScripts := &[]string{}
	appliedScripts := &[]string{}
	oldCheck, oldApply := runNftScriptCheck, runNftScript
	runNftScriptCheck = func(script string) error {
		*checkedScripts = append(*checkedScripts, script)
		return nil
	}
	runNftScript = func(script string) error {
		*appliedScripts = append(*appliedScripts, script)
		if apply != nil {
			return apply(script)
		}
		return nil
	}
	t.Cleanup(func() {
		runNftScriptCheck = oldCheck
		runNftScript = oldApply
	})
	return checkedScripts, appliedScripts
}

func stubSetsPresent(t *testing.T) {
	t.Helper()
	stubNftCommand(t, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" && (len(args) < 4 || args[3] != testNftTable) {
			return errors.New("validation table absent")
		}
		return nil
	})
}

func noTableJSON() []byte {
	return []byte(`{"nftables":[{"metainfo":{"version":"1.0.8","release_name":"test"}}]}`)
}

func tablesJSON(tables ...string) []byte {
	objects := []string{`{"metainfo":{"version":"1.0.8","release_name":"test"}}`}
	for _, table := range tables {
		objects = append(objects, fmt.Sprintf(`{"table":{"family":"inet","name":%q}}`, table))
	}
	return []byte(`{"nftables":[` + strings.Join(objects, ",") + `]}`)
}

func tableJSON(objects ...string) []byte {
	return tableJSONFor(testNftTable, objects...)
}

func tableJSONFor(table string, objects ...string) []byte {
	all := append([]string{fmt.Sprintf(`{"table":{"family":"inet","name":%q}}`, table)}, objects...)
	return []byte(`{"nftables":[{"metainfo":{"version":"1.0.8","release_name":"test"}},` + strings.Join(all, ",") + `]}`)
}

func setJSON(name, typ string, flags ...string) string {
	quoted := make([]string, 0, len(flags))
	for _, flag := range flags {
		quoted = append(quoted, fmt.Sprintf("%q", flag))
	}
	if len(quoted) == 0 {
		return fmt.Sprintf(`{"set":{"family":"inet","table":%q,"name":%q,"type":%q}}`, testNftTable, name, typ)
	}
	return fmt.Sprintf(`{"set":{"family":"inet","table":%q,"name":%q,"type":%q,"flags":[%s]}}`, testNftTable, name, typ, strings.Join(quoted, ","))
}

func chainJSON(name, comment, hook string, prio int, policy string) string {
	return fmt.Sprintf(
		`{"chain":{"family":"inet","table":%q,"name":%q,"type":"filter","hook":%q,"prio":%d,"policy":%q,"comment":%q}}`,
		testNftTable, name, hook, prio, policy, comment,
	)
}

func dropRuleJSON(chain, protocol, field, set string) string {
	return fmt.Sprintf(
		`{"rule":{"family":"inet","table":%q,"chain":%q,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":%q,"field":%q}},"right":"@%s"}},{"counter":{"packets":12,"bytes":960}},{"drop":null}]}}`,
		testNftTable, chain, protocol, field, set,
	)
}

func elementJSON(set string) string {
	return fmt.Sprintf(`{"element":{"family":"inet","table":%q,"name":%q,"elem":[{"elem":{"val":"192.0.2.10","timeout":300000}}]}}`, testNftTable, set)
}

func healthySets() []string {
	return []string{
		setJSON(familySetName(testNftSet, true), "ipv4_addr", "timeout"),
		setJSON(familySetName(testNftSet, false), "ipv6_addr", "timeout"),
		elementJSON(familySetName(testNftSet, true)),
	}
}

func healthyChain() []string {
	return []string{
		chainJSON(PacketDropChain, packetDropChainComment, "forward", -1, "accept"),
		dropRuleJSON(PacketDropChain, "ip", "saddr", familySetName(testNftSet, true)),
		dropRuleJSON(PacketDropChain, "ip6", "saddr", familySetName(testNftSet, false)),
	}
}

func writeTestIdentity(t *testing.T, table, set string) {
	t.Helper()
	if err := writePacketDropIdentity(packetDropIdentity{Table: table, Set: set, Chain: PacketDropChain}); err != nil {
		t.Fatalf("write identity: %v", err)
	}
}

func TestValidatePacketDropPrerequisitesRejectsReservedAndInvalidNames(t *testing.T) {
	for _, table := range []string{"fw4", "FW4", "filter", "nat", "raw", "inet", "ip"} {
		if err := ValidatePacketDropPrerequisites(table, testNftSet); err == nil ||
			!strings.Contains(err.Error(), "reserved or shared") {
			t.Fatalf("table %q: got %v, want reserved table error", table, err)
		}
	}
	if err := ValidatePacketDropPrerequisites("bad table", testNftSet); err == nil {
		t.Fatal("expected invalid identifier error")
	}
	if err := ValidatePacketDropPrerequisites(testNftTable, ""); err == nil {
		t.Fatal("expected empty set error")
	}
	if err := ValidatePacketDropPrerequisites(testNftTable, strings.Repeat("a", 253)); err == nil ||
		!strings.Contains(err.Error(), "252") {
		t.Fatalf("long set: got %v, want length error", err)
	}
}

func TestValidatePacketDropPrerequisitesAcceptsExactSetup(t *testing.T) {
	stubPrereqEnv(t)
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "list" && args[1] == "tables" {
			return noTableJSON(), nil
		}
		t.Fatalf("unexpected nft JSON args: %#v", args)
		return nil, nil
	})
	if err := ValidatePacketDropPrerequisites(testNftTable, testNftSet); err != nil {
		t.Fatalf("ValidatePacketDropPrerequisites: %v", err)
	}
}

func TestValidatePacketDropPrerequisitesRejectsOffloading(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value string
	}{
		{"firewall.@defaults[0].flow_offloading", "1"},
		{"firewall.@defaults[0].flow_offloading", "on"},
		{"firewall.@defaults[0].flow_offloading", "true"},
		{"firewall.@defaults[0].flow_offloading", "yes"},
		{"firewall.@defaults[0].flow_offloading_hw", "1"},
		{"firewall.@defaults[0].flow_offloading", "maybe"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			values := stubPrereqEnv(t)
			values[tc.key] = tc.value
			stubNftJSON(t, func(args ...string) ([]byte, error) {
				return noTableJSON(), nil
			})
			err := ValidatePacketDropPrerequisites(testNftTable, testNftSet)
			if err == nil || !strings.Contains(err.Error(), "flow_offloading") {
				t.Fatalf("got %v, want refusing offloading error", err)
			}
		})
	}
}

func TestValidatePacketDropPrerequisitesRejectsBadInclude(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"missing section", func(v map[string]string) { delete(v, "firewall.serpent_wrt") }, "not registered"},
		{"wrong type", func(v map[string]string) { v["firewall.serpent_wrt.type"] = "nftables" }, "type"},
		{"wrong path", func(v map[string]string) { v["firewall.serpent_wrt.path"] = "/tmp/other" }, "path"},
		{"not fw4 compatible", func(v map[string]string) { v["firewall.serpent_wrt.fw4_compatible"] = "0" }, "fw4_compatible"},
		{"disabled", func(v map[string]string) { v["firewall.serpent_wrt.enabled"] = "0" }, "disabled"},
		{"invalid enabled", func(v map[string]string) { v["firewall.serpent_wrt.enabled"] = "maybe" }, "boolean"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			values := stubPrereqEnv(t)
			tc.mutate(values)
			stubNftJSON(t, func(args ...string) ([]byte, error) { return noTableJSON(), nil })
			err := ValidatePacketDropPrerequisites(testNftTable, testNftSet)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestValidatePacketDropPrerequisitesRejectsMissingExecutablesAndInclude(t *testing.T) {
	t.Run("fw4 missing", func(t *testing.T) {
		stubPrereqEnv(t)
		lookPath = func(file string) (string, error) {
			if file == "fw4" {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + file, nil
		}
		err := ValidatePacketDropPrerequisites(testNftTable, testNftSet)
		if err == nil || !strings.Contains(err.Error(), "fw4 is unavailable") {
			t.Fatalf("got %v, want fw4 unavailable", err)
		}
	})
	t.Run("uci missing", func(t *testing.T) {
		stubPrereqEnv(t)
		lookPath = func(file string) (string, error) {
			if file == "uci" {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + file, nil
		}
		err := ValidatePacketDropPrerequisites(testNftTable, testNftSet)
		if err == nil || !strings.Contains(err.Error(), "uci is unavailable") {
			t.Fatalf("got %v, want uci unavailable", err)
		}
	})
	t.Run("include missing", func(t *testing.T) {
		stubPrereqEnv(t)
		fw4IncludePath = filepath.Join(t.TempDir(), "absent")
		// The uci fixture must report the same unavailable path so validation
		// reaches the availability check.
		runUCIOutput = func(args ...string) (string, error) {
			if len(args) == 3 && args[1] == "get" {
				switch args[2] {
				case "firewall.serpent_wrt":
					return "include\n", nil
				case "firewall.serpent_wrt.type":
					return "script\n", nil
				case "firewall.serpent_wrt.path":
					return fw4IncludePath + "\n", nil
				case "firewall.serpent_wrt.fw4_compatible":
					return "1\n", nil
				default:
					return "", errors.New("uci: Entry not found")
				}
			}
			return "", nil
		}
		err := ValidatePacketDropPrerequisites(testNftTable, testNftSet)
		if err == nil || !strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("got %v, want include unavailable", err)
		}
	})
}

func TestValidatePacketDropPrerequisitesRejectsSharedTable(t *testing.T) {
	stubPrereqEnv(t)
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return tablesJSON(testNftTable), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table":
			objects := append([]string{}, healthySets()...)
			objects = append(objects, setJSON("other_package_set", "ipv4_addr", "timeout"))
			return tableJSON(objects...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})
	err := ValidatePacketDropPrerequisites(testNftTable, testNftSet)
	if err == nil || !strings.Contains(err.Error(), "foreign set other_package_set") {
		t.Fatalf("got %v, want foreign set refusal", err)
	}
}

func TestValidatePacketDropPrerequisitesRejectsForeignResourceKinds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object string
		want   string
	}{
		{
			name:   "flowtable",
			object: fmt.Sprintf(`{"flowtable":{"family":"inet","table":%q,"name":"ft","hook":"ingress","dev":"eth0"}}`, testNftTable),
			want:   "foreign flowtable",
		},
		{
			name:   "map",
			object: fmt.Sprintf(`{"map":{"family":"inet","table":%q,"name":"verdicts","type":"ipv4_addr"}}`, testNftTable),
			want:   "foreign map",
		},
		{
			name:   "foreign chain",
			object: chainJSON("other_chain", "other owner", "forward", 0, "accept"),
			want:   "foreign chain other_chain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubPrereqEnv(t)
			objects := append(healthySets(), tc.object)
			stubNftJSON(t, func(args ...string) ([]byte, error) {
				switch {
				case len(args) == 2 && args[0] == "list" && args[1] == "tables":
					return tablesJSON(testNftTable), nil
				case len(args) == 4 && args[0] == "list" && args[1] == "table":
					return tableJSON(objects...), nil
				default:
					t.Fatalf("unexpected nft JSON args: %#v", args)
					return nil, nil
				}
			})
			err := ValidatePacketDropPrerequisites(testNftTable, testNftSet)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestValidatePacketDropPrerequisitesAcceptsOwnedResources(t *testing.T) {
	stubPrereqEnv(t)
	assertAllowed := func(t *testing.T, objects []string) {
		t.Helper()
		stubNftJSON(t, func(args ...string) ([]byte, error) {
			switch {
			case len(args) == 2 && args[0] == "list" && args[1] == "tables":
				return tablesJSON(testNftTable), nil
			case len(args) == 4 && args[0] == "list" && args[1] == "table":
				return tableJSON(objects...), nil
			default:
				t.Fatalf("unexpected nft JSON args: %#v", args)
				return nil, nil
			}
		})
		if err := ValidatePacketDropPrerequisites(testNftTable, testNftSet); err != nil {
			t.Fatalf("ValidatePacketDropPrerequisites: %v", err)
		}
	}
	t.Run("sets only", func(t *testing.T) {
		assertAllowed(t, healthySets())
	})
	t.Run("owned chain", func(t *testing.T) {
		objects := append(healthySets(), healthyChain()...)
		assertAllowed(t, objects)
	})
}

func TestReconcilePacketDropCreatesCheckedChainAndPreservesSets(t *testing.T) {
	withTestStateDir(t)
	stubPrereqEnv(t)
	stubSetsPresent(t)
	applied := false
	checked, appliedScripts := stubScripts(t, func(string) error {
		applied = true
		return nil
	})
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return noTableJSON(), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table":
			objects := append([]string{}, healthySets()...)
			if applied {
				objects = append(objects, healthyChain()...)
			}
			return tableJSON(objects...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})

	status, err := New(testNftTable, testNftSet, time.Hour).ReconcilePacketDrop(true)
	if err != nil {
		t.Fatalf("ReconcilePacketDrop: %v", err)
	}
	if !status.Enabled || status.State != PacketDropStateReady || status.Error != "" {
		t.Fatalf("status: got %+v, want ready", status)
	}
	if len(*appliedScripts) != 1 {
		t.Fatalf("applied scripts: got %d, want 1", len(*appliedScripts))
	}
	script := (*appliedScripts)[0]
	if len(*checked) == 0 || (*checked)[len(*checked)-1] != script {
		t.Fatal("applied script was not the checked transaction")
	}
	if !strings.Contains(script, "type filter hook forward priority -1; policy accept;") {
		t.Fatalf("chain definition missing: %s", script)
	}
	if strings.Count(script, "add rule") != 2 ||
		!strings.Contains(script, "ip saddr @"+familySetName(testNftSet, true)+" counter drop") ||
		!strings.Contains(script, "ip6 saddr @"+familySetName(testNftSet, false)+" counter drop") {
		t.Fatalf("expected exactly two source drop rules: %s", script)
	}
	for _, forbidden := range []string{
		"add set", "flush set", "delete set", "add element", "flush ruleset",
		"hook input", "hook output", "table inet fw4", "delete table",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script must not touch %q: %s", forbidden, script)
		}
	}

	info, err := os.Stat(packetDropStatePath())
	if err != nil {
		t.Fatalf("state file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode: got %o, want 600", info.Mode().Perm())
	}
	identity, ok, err := readPacketDropIdentity()
	if err != nil || !ok {
		t.Fatalf("read identity: ok=%t err=%v", ok, err)
	}
	want := packetDropIdentity{Table: testNftTable, Set: testNftSet, Chain: PacketDropChain}
	if identity != want {
		t.Fatalf("identity: got %+v, want %+v", identity, want)
	}
}

func TestReconcilePacketDropFailurePreservesPriorChain(t *testing.T) {
	withTestStateDir(t)
	stubPrereqEnv(t)
	stubSetsPresent(t)
	applied := false
	checked, appliedScripts := stubScripts(t, func(string) error {
		applied = true
		return nil
	})
	oldCheck := runNftScriptCheck
	runNftScriptCheck = func(script string) error {
		*checked = append(*checked, script)
		if strings.Contains(script, "add set") {
			return nil
		}
		return errors.New("kernel rejected transaction")
	}
	t.Cleanup(func() { runNftScriptCheck = oldCheck })
	objects := append(healthySets(), healthyChain()...)
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return tablesJSON(testNftTable), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table":
			return tableJSON(objects...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})

	status, err := New(testNftTable, testNftSet, time.Hour).ReconcilePacketDrop(true)
	if err == nil || !strings.Contains(err.Error(), "kernel rejected transaction") {
		t.Fatalf("error: got %v, want checked transaction failure", err)
	}
	if status.State != PacketDropStateFailed || status.Error == "" {
		t.Fatalf("status: got %+v, want failed with error", status)
	}
	if applied {
		t.Fatal("failed --check must not apply a transaction")
	}
	if len(*appliedScripts) != 0 {
		t.Fatalf("applied scripts: got %d, want 0", len(*appliedScripts))
	}
	if _, err := os.Stat(packetDropStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file should not exist after failure, got %v", err)
	}
}

func TestReconcilePacketDropReplacesOwnedDefinitionDrift(t *testing.T) {
	withTestStateDir(t)
	stubPrereqEnv(t)
	stubSetsPresent(t)
	applied := false
	checked, appliedScripts := stubScripts(t, func(string) error {
		applied = true
		return nil
	})
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return tablesJSON(testNftTable), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table":
			objects := append([]string{}, healthySets()...)
			if applied {
				objects = append(objects, healthyChain()...)
			} else {
				objects = append(objects,
					chainJSON(PacketDropChain, packetDropChainComment, "input", 0, "accept"),
					dropRuleJSON(PacketDropChain, "ip", "saddr", familySetName(testNftSet, true)),
					dropRuleJSON(PacketDropChain, "ip6", "saddr", familySetName(testNftSet, false)),
				)
			}
			return tableJSON(objects...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})

	status, err := New(testNftTable, testNftSet, time.Hour).ReconcilePacketDrop(true)
	if err != nil {
		t.Fatalf("ReconcilePacketDrop: %v", err)
	}
	if status.State != PacketDropStateReady {
		t.Fatalf("status: got %+v, want ready", status)
	}
	if len(*appliedScripts) != 1 || len(*checked) == 0 || (*checked)[len(*checked)-1] != (*appliedScripts)[0] {
		t.Fatal("replacement was not one checked transaction")
	}
	script := (*appliedScripts)[0]
	for _, fragment := range []string{
		"flush chain inet " + testNftTable + " " + PacketDropChain,
		"delete chain inet " + testNftTable + " " + PacketDropChain,
		"add chain inet " + testNftTable + " " + PacketDropChain + " { type filter hook forward priority -1;",
	} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("replacement script missing %q: %s", fragment, script)
		}
	}
}

func TestReconcilePacketDropDoesNotApplyWithoutPersistedIdentity(t *testing.T) {
	withTestStateDir(t)
	stubPrereqEnv(t)
	stubSetsPresent(t)
	if err := os.Mkdir(packetDropStatePath(), 0o700); err != nil {
		t.Fatalf("create state-path directory: %v", err)
	}
	_, appliedScripts := stubScripts(t, nil)
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return noTableJSON(), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table":
			return tableJSON(healthySets()...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})

	status, err := New(testNftTable, testNftSet, time.Hour).ReconcilePacketDrop(true)
	if err == nil {
		t.Fatal("expected identity persistence failure")
	}
	if status.State != PacketDropStateFailed || status.Error == "" {
		t.Fatalf("status: got %+v, want failed", status)
	}
	if len(*appliedScripts) != 0 {
		t.Fatal("kernel must not change when identity cannot be persisted")
	}
}

func TestReconcilePacketDropRejectsForeignChain(t *testing.T) {
	withTestStateDir(t)
	stubPrereqEnv(t)
	stubSetsPresent(t)
	checked, appliedScripts := stubScripts(t, nil)
	objects := append(healthySets(), chainJSON(PacketDropChain, "foreign owner", "forward", -1, "accept"))
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return tablesJSON(testNftTable), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table":
			return tableJSON(objects...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})

	status, err := New(testNftTable, testNftSet, time.Hour).ReconcilePacketDrop(true)
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("error: got %v, want foreign chain refusal", err)
	}
	if status.State != PacketDropStateFailed {
		t.Fatalf("status: got %+v, want failed", status)
	}
	if len(*checked) != 0 || len(*appliedScripts) != 0 {
		t.Fatalf("no script may run on a foreign chain: checked=%d applied=%d", len(*checked), len(*appliedScripts))
	}
}

func TestReconcilePacketDropRejectsBadSetDefinitions(t *testing.T) {
	tests := []struct {
		name    string
		objects []string
		want    string
	}{
		{
			name: "wrong type",
			objects: []string{
				setJSON(familySetName(testNftSet, true), "ipv6_addr", "timeout"),
				setJSON(familySetName(testNftSet, false), "ipv6_addr", "timeout"),
			},
			want: "must have type ipv4_addr",
		},
		{
			name: "not timed",
			objects: []string{
				setJSON(familySetName(testNftSet, true), "ipv4_addr"),
				setJSON(familySetName(testNftSet, false), "ipv6_addr", "timeout"),
			},
			want: "timeout semantics",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withTestStateDir(t)
			stubPrereqEnv(t)
			stubSetsPresent(t)
			checked, appliedScripts := stubScripts(t, nil)
			objects := append([]string{}, tc.objects...)
			stubNftJSON(t, func(args ...string) ([]byte, error) {
				switch {
				case len(args) == 2 && args[0] == "list" && args[1] == "tables":
					return tablesJSON(testNftTable), nil
				case len(args) == 4 && args[0] == "list" && args[1] == "table":
					return tableJSON(objects...), nil
				default:
					t.Fatalf("unexpected nft JSON args: %#v", args)
					return nil, nil
				}
			})
			status, err := New(testNftTable, testNftSet, time.Hour).ReconcilePacketDrop(true)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error: got %v, want %q", err, tc.want)
			}
			if status.State != PacketDropStateFailed {
				t.Fatalf("status: got %+v, want failed", status)
			}
			if len(*checked) != 0 || len(*appliedScripts) != 0 {
				t.Fatal("set validation must fail before any chain transaction")
			}
		})
	}
}

func TestReconcilePacketDropRefusesIdentityMigration(t *testing.T) {
	withTestStateDir(t)
	stubPrereqEnv(t)
	writeTestIdentity(t, "old_table", "old_set")
	checked, appliedScripts := stubScripts(t, nil)
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		if len(args) == 2 && args[0] == "list" && args[1] == "tables" {
			return noTableJSON(), nil
		}
		t.Fatalf("unexpected nft JSON args: %#v", args)
		return nil, nil
	})

	status, err := New("new_table", "new_set", time.Hour).ReconcilePacketDrop(true)
	if err == nil || !strings.Contains(err.Error(), "run firewall disable first") {
		t.Fatalf("error: got %v, want migration refusal", err)
	}
	if status.State != PacketDropStateFailed {
		t.Fatalf("status: got %+v, want failed", status)
	}
	if len(*checked) != 0 || len(*appliedScripts) != 0 {
		t.Fatal("identity migration must not touch either chain")
	}
	identity, ok, err := readPacketDropIdentity()
	if err != nil || !ok || identity.Table != "old_table" || identity.Set != "old_set" {
		t.Fatalf("identity changed or lost: %+v ok=%t err=%v", identity, ok, err)
	}
}

func TestDisablePacketDropUsesPersistedIdentityWithoutConfig(t *testing.T) {
	withTestStateDir(t)
	writeTestIdentity(t, testNftTable, testNftSet)
	checked, appliedScripts := stubScripts(t, nil)
	uciCalls := 0
	oldUCI := runUCIOutput
	runUCIOutput = func(args ...string) (string, error) {
		uciCalls++
		return "", errors.New("uci must not be consulted")
	}
	t.Cleanup(func() { runUCIOutput = oldUCI })
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return tablesJSON(testNftTable), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table" && args[3] == testNftTable:
			objects := append(healthySets(), healthyChain()...)
			return tableJSON(objects...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})

	if err := DisablePacketDrop(); err != nil {
		t.Fatalf("DisablePacketDrop: %v", err)
	}
	if uciCalls != 0 {
		t.Fatalf("disable consulted configuration %d times", uciCalls)
	}
	if len(*checked) != 1 || len(*appliedScripts) != 1 {
		t.Fatalf("scripts: checked=%d applied=%d, want 1 each", len(*checked), len(*appliedScripts))
	}
	script := (*appliedScripts)[0]
	if !strings.Contains(script, "flush chain inet "+testNftTable+" "+PacketDropChain) ||
		!strings.Contains(script, "delete chain inet "+testNftTable+" "+PacketDropChain) {
		t.Fatalf("disable script did not remove the recorded chain: %s", script)
	}
	if strings.Contains(script, "set") || strings.Contains(script, "ruleset") {
		t.Fatalf("disable must keep sets and never flush the ruleset: %s", script)
	}
	if _, err := os.Stat(packetDropStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file should be removed, got %v", err)
	}
}

func TestDisablePacketDropIsIdempotentWhenOwnedResourcesAreMissing(t *testing.T) {
	t.Run("table missing", func(t *testing.T) {
		withTestStateDir(t)
		writeTestIdentity(t, testNftTable, testNftSet)
		checked, appliedScripts := stubScripts(t, nil)
		stubNftJSON(t, func(args ...string) ([]byte, error) {
			if len(args) == 2 && args[0] == "list" && args[1] == "tables" {
				return noTableJSON(), nil
			}
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		})
		if err := DisablePacketDrop(); err != nil {
			t.Fatalf("DisablePacketDrop: %v", err)
		}
		if len(*checked) != 0 || len(*appliedScripts) != 0 {
			t.Fatal("missing table must not produce a transaction")
		}
		if _, err := os.Stat(packetDropStatePath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("state file should be removed")
		}
	})
	t.Run("chain missing", func(t *testing.T) {
		withTestStateDir(t)
		writeTestIdentity(t, testNftTable, testNftSet)
		checked, appliedScripts := stubScripts(t, nil)
		stubNftJSON(t, func(args ...string) ([]byte, error) {
			switch {
			case len(args) == 2 && args[0] == "list" && args[1] == "tables":
				return tablesJSON(testNftTable), nil
			case len(args) == 4 && args[0] == "list" && args[1] == "table":
				return tableJSON(healthySets()...), nil
			default:
				t.Fatalf("unexpected nft JSON args: %#v", args)
				return nil, nil
			}
		})
		if err := DisablePacketDrop(); err != nil {
			t.Fatalf("DisablePacketDrop: %v", err)
		}
		if len(*checked) != 0 || len(*appliedScripts) != 0 {
			t.Fatal("missing chain must not produce a transaction")
		}
		if _, err := os.Stat(packetDropStatePath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("state file should be removed")
		}
	})
}

func TestDisablePacketDropRefusesUnownedOrReservedIdentity(t *testing.T) {
	t.Run("unowned chain", func(t *testing.T) {
		withTestStateDir(t)
		writeTestIdentity(t, testNftTable, testNftSet)
		checked, appliedScripts := stubScripts(t, nil)
		objects := append(healthySets(), chainJSON(PacketDropChain, "other owner", "forward", -1, "accept"))
		stubNftJSON(t, func(args ...string) ([]byte, error) {
			switch {
			case len(args) == 2 && args[0] == "list" && args[1] == "tables":
				return tablesJSON(testNftTable), nil
			case len(args) == 4 && args[0] == "list" && args[1] == "table":
				return tableJSON(objects...), nil
			default:
				t.Fatalf("unexpected nft JSON args: %#v", args)
				return nil, nil
			}
		})
		err := DisablePacketDrop()
		if err == nil || !strings.Contains(err.Error(), "unowned") {
			t.Fatalf("error: got %v, want unowned refusal", err)
		}
		if len(*checked) != 0 || len(*appliedScripts) != 0 {
			t.Fatal("unowned chain must not be removed")
		}
		if _, err := os.Stat(packetDropStatePath()); err != nil {
			t.Fatalf("state should remain for operator recovery: %v", err)
		}
	})
	t.Run("reserved table", func(t *testing.T) {
		withTestStateDir(t)
		writeTestIdentity(t, "fw4", testNftSet)
		checked, appliedScripts := stubScripts(t, nil)
		stubNftJSON(t, func(args ...string) ([]byte, error) {
			t.Fatalf("state with reserved table must not reach nft: %#v", args)
			return nil, nil
		})
		err := DisablePacketDrop()
		if err == nil || !strings.Contains(err.Error(), "reserved or shared") {
			t.Fatalf("error: got %v, want reserved table refusal", err)
		}
		if len(*checked) != 0 || len(*appliedScripts) != 0 {
			t.Fatal("reserved table must not be touched")
		}
	})
}

func TestCheckPacketDropUsesJSONHookAndRuleReferences(t *testing.T) {
	ready := append(healthySets(), healthyChain()...)
	tests := []struct {
		name    string
		enabled bool
		objects []string
		want    string
	}{
		{name: "disabled", enabled: false, want: PacketDropStateDisabled},
		{name: "ready", enabled: true, objects: ready, want: PacketDropStateReady},
		{name: "missing chain", enabled: true, objects: healthySets(), want: PacketDropStateFailed},
		{
			name:    "wrong hook",
			enabled: true,
			objects: append(healthySets(), append([]string{chainJSON(PacketDropChain, packetDropChainComment, "input", 0, "accept")}, healthyChain()[1:]...)...),
			want:    PacketDropStateFailed,
		},
		{
			name:    "missing rule",
			enabled: true,
			objects: append(healthySets(), chainJSON(PacketDropChain, packetDropChainComment, "forward", -1, "accept"), dropRuleJSON(PacketDropChain, "ip", "saddr", familySetName(testNftSet, true))),
			want:    PacketDropStateFailed,
		},
		{
			name:    "extra foreign rule",
			enabled: true,
			objects: append(ready, dropRuleJSON(PacketDropChain, "ip", "daddr", familySetName(testNftSet, true))),
			want:    PacketDropStateFailed,
		},
		{
			name:    "foreign chain comment",
			enabled: true,
			objects: append(healthySets(), chainJSON(PacketDropChain, "someone else", "forward", -1, "accept"), dropRuleJSON(PacketDropChain, "ip", "saddr", familySetName(testNftSet, true)), dropRuleJSON(PacketDropChain, "ip6", "saddr", familySetName(testNftSet, false))),
			want:    PacketDropStateFailed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubPrereqEnv(t)
			calls := 0
			stubNftJSON(t, func(args ...string) ([]byte, error) {
				calls++
				return tableJSON(tc.objects...), nil
			})
			checked, appliedScripts := stubScripts(t, nil)
			status := New(testNftTable, testNftSet, time.Hour).CheckPacketDrop(tc.enabled)
			if status.State != tc.want {
				t.Fatalf("state: got %+v, want %s", status, tc.want)
			}
			if tc.enabled != status.Enabled {
				t.Fatalf("enabled: got %t, want %t", status.Enabled, tc.enabled)
			}
			if tc.want == PacketDropStateFailed && status.Error == "" {
				t.Fatal("failed status must include an error")
			}
			if len(*checked) != 0 || len(*appliedScripts) != 0 {
				t.Fatal("CheckPacketDrop must not apply changes")
			}
			if !tc.enabled && calls != 0 {
				t.Fatalf("disabled check invoked nft %d times", calls)
			}
		})
	}
}

func TestEnsureResourcesReportsRecreationAndPreservesExistingSets(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withTestStateDir(t)
		stubSetsPresent(t)
		checked, appliedScripts := stubScripts(t, nil)
		recreated, err := New(testNftTable, testNftSet, time.Hour).EnsureResources()
		if err != nil || recreated {
			t.Fatalf("EnsureResources: recreated=%t err=%v", recreated, err)
		}
		if len(*appliedScripts) != 0 {
			t.Fatal("existing resources must not produce an applied transaction")
		}
		if len(*checked) != 1 || !strings.Contains((*checked)[0], "add set") {
			t.Fatalf("expected only the parser validation batch, got %#v", *checked)
		}
	})
	t.Run("IPv6 set missing", func(t *testing.T) {
		withTestStateDir(t)
		stubNftCommand(t, func(args ...string) error {
			if len(args) > 1 && args[1] == "table" && (len(args) < 4 || args[3] != testNftTable) {
				return errors.New("validation table absent")
			}
			if len(args) > 4 && args[1] == "set" && args[4] == familySetName(testNftSet, false) {
				return errors.New("IPv6 set missing")
			}
			return nil
		})
		checked, appliedScripts := stubScripts(t, nil)
		recreated, err := New(testNftTable, testNftSet, time.Hour).EnsureResources()
		if err != nil || !recreated {
			t.Fatalf("EnsureResources: recreated=%t err=%v", recreated, err)
		}
		if len(*appliedScripts) != 1 || len(*checked) == 0 || (*checked)[len(*checked)-1] != (*appliedScripts)[0] {
			t.Fatalf("checked and applied batches differ: %#v %#v", *checked, *appliedScripts)
		}
		script := (*appliedScripts)[0]
		if !strings.Contains(script, familySetName(testNftSet, false)) ||
			strings.Contains(script, familySetName(testNftSet, true)) ||
			strings.Contains(script, "add table") {
			t.Fatalf("repair must add only the missing set: %s", script)
		}
	})
	t.Run("table missing", func(t *testing.T) {
		withTestStateDir(t)
		stubNftCommand(t, func(args ...string) error {
			if len(args) > 1 && args[1] == "table" && (len(args) < 4 || args[3] != testNftTable) {
				return errors.New("validation table absent")
			}
			if len(args) > 1 && args[1] == "table" {
				return errors.New("table missing")
			}
			return nil
		})
		checked, appliedScripts := stubScripts(t, nil)
		recreated, err := New(testNftTable, testNftSet, time.Hour).EnsureResources()
		if err != nil || !recreated {
			t.Fatalf("EnsureResources: recreated=%t err=%v", recreated, err)
		}
		if len(*appliedScripts) != 1 || len(*checked) == 0 || (*checked)[len(*checked)-1] != (*appliedScripts)[0] {
			t.Fatal("expected one checked transaction")
		}
		script := (*appliedScripts)[0]
		if !strings.Contains(script, "add table inet "+testNftTable) ||
			!strings.Contains(script, familySetName(testNftSet, true)) ||
			!strings.Contains(script, familySetName(testNftSet, false)) {
			t.Fatalf("recreation batch is incomplete: %s", script)
		}
	})
	t.Run("apply failure", func(t *testing.T) {
		withTestStateDir(t)
		stubNftCommand(t, func(args ...string) error {
			if len(args) > 1 && args[1] == "table" && (len(args) < 4 || args[3] != testNftTable) {
				return errors.New("validation table absent")
			}
			if len(args) > 4 && args[1] == "set" && args[4] == familySetName(testNftSet, false) {
				return errors.New("IPv6 set missing")
			}
			return nil
		})
		stubScripts(t, func(string) error { return errors.New("apply failed") })
		recreated, err := New(testNftTable, testNftSet, time.Hour).EnsureResources()
		if err == nil || !strings.Contains(err.Error(), "apply failed") {
			t.Fatalf("error: got %v, want apply failure", err)
		}
		if recreated {
			t.Fatal("failed recreation must not report success")
		}
	})
}

func TestBlockReinsertsCachedOffenderAfterExternalResourceLoss(t *testing.T) {
	withTestStateDir(t)
	ip := net.ParseIP("198.51.100.7")
	var scripts []string
	restoreScripts := stubNftScript(t, func(script string) error {
		scripts = append(scripts, script)
		return nil
	})
	defer restoreScripts()

	listCalls := 0
	oldList := runNftListSet
	runNftListSet = func(table, set string) ([]string, error) {
		listCalls++
		if set != familySetName(testNftSet, true) {
			t.Fatalf("unexpected set: %s", set)
		}
		return nil, nil
	}
	t.Cleanup(func() { runNftListSet = oldList })

	e := New(testNftTable, testNftSet, time.Hour)
	e.mu.Lock()
	e.blocked[ip.String()] = time.Now().Add(time.Hour)
	e.mu.Unlock()

	if err := e.Block(ip); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if listCalls != 1 {
		t.Fatalf("membership checks: got %d, want 1", listCalls)
	}
	if len(scripts) != 1 || !strings.Contains(scripts[0], "add element inet "+testNftTable) {
		t.Fatalf("cached offender was not reinserted: %#v", scripts)
	}
	if !e.IsBlocked(ip) {
		t.Fatal("reinserted offender must remain cached")
	}
}

func TestBlockRecreatesSetsBeforeReinsertingCachedOffender(t *testing.T) {
	withTestStateDir(t)
	ip := net.ParseIP("198.51.100.8")
	_, appliedScripts := stubScripts(t, nil)
	stubNftCommand(t, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" && (len(args) < 4 || args[3] != testNftTable) {
			return errors.New("validation table absent")
		}
		return nil
	})
	listCalls := 0
	oldList := runNftListSet
	runNftListSet = func(table, set string) ([]string, error) {
		listCalls++
		if listCalls == 1 {
			return nil, errors.New("set missing after firewall flush")
		}
		return nil, nil
	}
	t.Cleanup(func() { runNftListSet = oldList })

	e := New(testNftTable, testNftSet, time.Hour)
	e.mu.Lock()
	e.blocked[ip.String()] = time.Now().Add(time.Hour)
	e.mu.Unlock()

	if err := e.Block(ip); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if listCalls != 2 {
		t.Fatalf("membership checks: got %d, want 2", listCalls)
	}
	if len(*appliedScripts) != 1 || !strings.Contains((*appliedScripts)[0], "add element inet "+testNftTable) {
		t.Fatalf("cached offender was not reinserted after set recovery: %#v", *appliedScripts)
	}
}

func TestBlockSkipsCachedOffenderStillPresentInKernel(t *testing.T) {
	ip := net.ParseIP("198.51.100.9")
	restoreScripts := stubNftScript(t, func(string) error {
		t.Fatal("present kernel element must not be re-added")
		return nil
	})
	defer restoreScripts()
	oldList := runNftListSet
	runNftListSet = func(table, set string) ([]string, error) {
		return []string{ip.String()}, nil
	}
	t.Cleanup(func() { runNftListSet = oldList })

	e := New(testNftTable, testNftSet, time.Hour)
	e.mu.Lock()
	e.blocked[ip.String()] = time.Now().Add(time.Hour)
	e.mu.Unlock()
	if err := e.Block(ip); err != nil {
		t.Fatalf("Block: %v", err)
	}
}

func TestReconcilePacketDropDisabledRemovesRecordedChain(t *testing.T) {
	withTestStateDir(t)
	writeTestIdentity(t, testNftTable, testNftSet)
	checked, appliedScripts := stubScripts(t, nil)
	uciCalls := 0
	oldUCI := runUCIOutput
	runUCIOutput = func(args ...string) (string, error) {
		uciCalls++
		return "", errors.New("uci must not be consulted")
	}
	t.Cleanup(func() { runUCIOutput = oldUCI })
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		switch {
		case len(args) == 2 && args[0] == "list" && args[1] == "tables":
			return tablesJSON(testNftTable), nil
		case len(args) == 4 && args[0] == "list" && args[1] == "table":
			return tableJSON(append(healthySets(), healthyChain()...)...), nil
		default:
			t.Fatalf("unexpected nft JSON args: %#v", args)
			return nil, nil
		}
	})

	status, err := New(testNftTable, testNftSet, time.Hour).ReconcilePacketDrop(false)
	if err != nil {
		t.Fatalf("ReconcilePacketDrop(false): %v", err)
	}
	if status.Enabled || status.State != PacketDropStateDisabled {
		t.Fatalf("status: got %+v, want disabled", status)
	}
	if uciCalls != 0 {
		t.Fatalf("disable consulted configuration %d times", uciCalls)
	}
	if len(*checked) != 1 || len(*appliedScripts) != 1 {
		t.Fatalf("scripts: checked=%d applied=%d", len(*checked), len(*appliedScripts))
	}
	if !strings.Contains((*appliedScripts)[0], "delete chain inet "+testNftTable+" "+PacketDropChain) {
		t.Fatalf("disable did not remove the owned chain: %s", (*appliedScripts)[0])
	}
	if _, err := os.Stat(packetDropStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state file should be removed")
	}
}

func TestPacketDropStateRejectsSymlinkAndInsecureMode(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		withTestStateDir(t)
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte(`{"table":"serpent_wrt","set":"blocked_ips","chain":"serpent_forward"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, packetDropStatePath()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readPacketDropIdentity(); err == nil {
			t.Fatal("expected symlink state to be rejected")
		}
	})
	t.Run("insecure mode", func(t *testing.T) {
		withTestStateDir(t)
		writeTestIdentity(t, testNftTable, testNftSet)
		if err := os.Chmod(packetDropStatePath(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readPacketDropIdentity(); err == nil || !strings.Contains(err.Error(), "accessible") {
			t.Fatalf("got %v, want insecure mode rejection", err)
		}
	})
}

func TestFirewallLockRejectsSymlink(t *testing.T) {
	withTestStateDir(t)
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), firewallLockPath()); err != nil {
		t.Fatal(err)
	}
	stubSetsPresent(t)
	if _, err := New(testNftTable, testNftSet, time.Hour).EnsureResources(); err == nil {
		t.Fatal("expected symlinked lock to be rejected")
	}
}

func TestPacketDropPrerequisitesRejectsUnreadablePresentOptions(t *testing.T) {
	for _, key := range []string{
		"firewall.@defaults[0].flow_offloading",
		"firewall.@defaults[0].flow_offloading_hw",
		"firewall.serpent_wrt.enabled",
	} {
		t.Run(key, func(t *testing.T) {
			values := stubPrereqEnv(t)
			values[key] = "1"
			base := runUCIOutput
			runUCIOutput = func(args ...string) (string, error) {
				if args[1] == "get" && args[2] == key {
					return "", errors.New("option read failed")
				}
				if args[1] == "show" && args[2] != "firewall" {
					return key + "='1'\n", nil
				}
				return base(args...)
			}
			stubNftJSON(t, func(...string) ([]byte, error) { return noTableJSON(), nil })
			if err := ValidatePacketDropPrerequisites(testNftTable, testNftSet); err == nil {
				t.Fatal("an unreadable present safety option must prevent packet-drop activation")
			}
		})
	}
}

func TestEnsureResourcesClearsOnlyLostFamilyCache(t *testing.T) {
	withTestStateDir(t)
	stubPrereqEnv(t)
	stubScripts(t, nil)
	e := New(testNftTable, testNftSet, time.Minute)
	v4, v6 := net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")
	for _, ip := range []net.IP{v4, v6} {
		if err := e.Block(ip); err != nil {
			t.Fatal(err)
		}
	}
	stubNftCommand(t, func(args ...string) error {
		if len(args) > 1 && args[1] == "table" && args[len(args)-1] != testNftTable {
			return errors.New("validation table absent")
		}
		if args[len(args)-1] == testNftSet+"_v6" {
			return errors.New("IPv6 set lost")
		}
		return nil
	})
	recreated, err := e.EnsureResources()
	if err != nil || !recreated {
		t.Fatalf("restore missing family: recreated=%t err=%v", recreated, err)
	}
	if e.IsBlocked(v6) {
		t.Fatal("lost IPv6 resources must clear stale cached blocks")
	}
	if !e.IsBlocked(v4) {
		t.Fatal("the intact IPv4 set must retain its cached blocks and timeouts")
	}
}

func TestDisabledPacketDropReportsResidualOwnedChain(t *testing.T) {
	withTestStateDir(t)
	writeTestIdentity(t, testNftTable, testNftSet)
	stubNftJSON(t, func(args ...string) ([]byte, error) {
		if len(args) == 2 {
			return tablesJSON(testNftTable), nil
		}
		return tableJSON(append(healthySets(), healthyChain()...)...), nil
	})
	status := New(testNftTable, testNftSet, time.Minute).CheckPacketDrop(false)
	if status.Enabled || status.State != PacketDropStateFailed || status.Error == "" {
		t.Fatalf("a residual owned drop chain must not appear disabled: %+v", status)
	}
}

func TestPacketDropStatusRejectsOffloadingAfterActivation(t *testing.T) {
	values := stubPrereqEnv(t)
	values["firewall.@defaults[0].flow_offloading"] = "1"
	stubNftJSON(t, func(...string) ([]byte, error) {
		return tableJSON(append(healthySets(), healthyChain()...)...), nil
	})
	status := New(testNftTable, testNftSet, time.Minute).CheckPacketDrop(true)
	if status.State != PacketDropStateFailed || status.Error == "" {
		t.Fatalf("offloading must invalidate readiness even with intact drop rules: %+v", status)
	}
}
