package main

import (
	"errors"
	"flag"
	"io"
	"time"

	"github.com/ecan0/serpent-wrt/internal/enforcer"
)

var (
	reconcilePacketDropPolicy = func(table, set string, duration time.Duration, enabled bool) (enforcer.PacketDropStatus, error) {
		return enforcer.New(table, set, duration).ReconcilePacketDrop(enabled)
	}
	disablePacketDropPolicy = enforcer.DisablePacketDrop
)

// runFirewall dispatches the fw4 integration commands. Disable never loads the
// configuration: it uses the identity persisted by a previous apply so a bad
// configuration edit cannot leave an owned drop chain behind.
func runFirewall(args []string, stdout, stderr io.Writer, defaultConfigPath string) int {
	fs := flag.NewFlagSet("serpent-wrt firewall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "path to config file")
	fs.Usage = func() {
		writef(stderr, "Usage: serpent-wrt firewall [--config path] reconcile|disable\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() == 0 {
		writef(stderr, "serpent-wrt: firewall: expected reconcile or disable\n")
		fs.Usage()
		return 2
	}
	subcommand := fs.Arg(0)
	rest := fs.Args()[1:]
	switch subcommand {
	case "reconcile":
		return runFirewallReconcile(rest, *cfgPath, stdout, stderr)
	case "disable":
		return runFirewallDisable(rest, *cfgPath, stdout, stderr)
	default:
		writef(stderr, "serpent-wrt: firewall: unknown command %q\n", subcommand)
		return 2
	}
}

func runFirewallReconcile(args []string, defaultConfigPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serpent-wrt firewall reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "path to config file")
	fs.Usage = func() {
		writef(stderr, "Usage: serpent-wrt firewall reconcile [--config path]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		writef(stderr, "serpent-wrt: firewall reconcile: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	cfg, _, _, err := checkConfig(*cfgPath)
	if err != nil {
		writef(stderr, "serpent-wrt: firewall reconcile failed: %v\n", err)
		return 1
	}

	status, err := reconcilePacketDropPolicy(cfg.NftTable, cfg.NftSet, cfg.BlockDuration, cfg.PacketDropEnabled)
	if err != nil {
		writef(stderr, "serpent-wrt: firewall reconcile failed: %v\n", err)
		return 1
	}
	if cfg.PacketDropEnabled && status.State != enforcer.PacketDropStateReady {
		detail := status.Error
		if detail == "" {
			detail = "packet drop policy is not active"
		}
		writef(stderr, "serpent-wrt: firewall reconcile failed: packet drop state=%s: %s\n", status.State, detail)
		return 1
	}
	if status.ResourcesLost {
		writef(stderr, "serpent-wrt: nft resources were lost; missing resources were recreated, but expired or lost set elements cannot be restored\n")
	}
	writef(stdout, "serpent-wrt: firewall reconcile: table=%s set=%s packet_drop=%s\n",
		cfg.NftTable, cfg.NftSet, status.State)
	return 0
}

func runFirewallDisable(args []string, defaultConfigPath string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serpent-wrt firewall disable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	_ = fs.String("config", defaultConfigPath, "accepted for CLI compatibility; disable uses persisted table identity")
	fs.Usage = func() {
		writef(stderr, "Usage: serpent-wrt firewall disable [--config path]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		writef(stderr, "serpent-wrt: firewall disable: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	if err := disablePacketDropPolicy(); err != nil {
		writef(stderr, "serpent-wrt: firewall disable failed: %v\n", err)
		return 1
	}
	writef(stdout, "serpent-wrt: firewall disable: packet drop policy removed\n")
	return 0
}
