package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ecan0/serpent-wrt/internal/api"
	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/enforcer"
	"github.com/ecan0/serpent-wrt/internal/events"
	"github.com/ecan0/serpent-wrt/internal/feed"
	"github.com/ecan0/serpent-wrt/internal/runtime"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "configtest" {
		return runConfigtest(args[1:], stdout, stderr, "/etc/serpent-wrt/serpent-wrt.yaml")
	}
	if len(args) > 0 && args[0] == "nftcheck" {
		return runNftcheck(args[1:], stdout, stderr, "/etc/serpent-wrt/serpent-wrt.yaml")
	}

	fs := flag.NewFlagSet("serpent-wrt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/serpent-wrt/serpent-wrt.yaml", "path to config file")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		writef(stderr, "Usage: serpent-wrt [--config path] [configtest|nftcheck]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		writef(stdout, "serpent-wrt version=%s commit=%s build_date=%s\n", version, commit, buildDate)
		return 0
	}

	if fs.NArg() > 0 {
		switch fs.Arg(0) {
		case "configtest":
			return runConfigtest(fs.Args()[1:], stdout, stderr, *cfgPath)
		case "nftcheck":
			return runNftcheck(fs.Args()[1:], stdout, stderr, *cfgPath)
		default:
			writef(stderr, "serpent-wrt: unknown command %q\n", fs.Arg(0))
			return 2
		}
	}

	return runDaemon(*cfgPath, stderr)
}

func runNftcheck(args []string, stdout, stderr io.Writer, defaultConfigPath string) int {
	fs := flag.NewFlagSet("serpent-wrt nftcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "path to config file")
	format := fs.String("format", "human", "output format: human or json")
	fs.Usage = func() {
		writef(stderr, "Usage: serpent-wrt nftcheck [--config path] [--format human|json]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		writef(stderr, "serpent-wrt: nftcheck: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *format != "human" && *format != "json" {
		writef(stderr, "serpent-wrt: nftcheck: invalid format %q\n", *format)
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		if *format == "json" {
			writeNftcheckJSON(stdout, nftcheckResult{
				Status: "error",
				Error:  "config: " + err.Error(),
			})
			return 1
		}
		writef(stderr, "serpent-wrt: nftcheck failed: config: %v\n", err)
		return 1
	}
	if !cfg.EnforcementEnabled {
		if *format == "json" {
			writeNftcheckJSON(stdout, nftcheckResult{
				Status:             "skipped",
				EnforcementEnabled: false,
				Table:              cfg.NftTable,
				Set:                cfg.NftSet,
				Diagnostic:         "enforcement disabled",
			})
			return 0
		}
		writef(stdout, "serpent-wrt: nft check skipped: enforcement disabled (table=%s set=%s)\n", cfg.NftTable, cfg.NftSet)
		return 0
	}

	enf := enforcer.New(cfg.NftTable, cfg.NftSet, cfg.BlockDuration)
	check := enf.Check()
	result := nftcheckResult{
		Status:             "ok",
		EnforcementEnabled: true,
		Table:              cfg.NftTable,
		Set:                cfg.NftSet,
		Available:          check.Available,
		TablePresent:       check.TablePresent,
		SetPresent:         check.SetPresent,
		Error:              check.Error,
	}
	if !check.Available {
		result.Status = "failed"
		result.Diagnostic = "nft unavailable"
		if *format == "json" {
			writeNftcheckJSON(stdout, result)
			return 1
		}
		writef(stderr, "serpent-wrt: nft check failed: nft unavailable: %s\n", check.Error)
		return 1
	}
	if !check.TablePresent {
		result.Status = "failed"
		result.Diagnostic = "missing table"
		if *format == "json" {
			writeNftcheckJSON(stdout, result)
			return 1
		}
		writef(stderr, "serpent-wrt: nft check failed: missing table inet %s: %s\n", cfg.NftTable, check.Error)
		return 1
	}
	if !check.SetPresent {
		result.Status = "failed"
		result.Diagnostic = "missing set"
		if *format == "json" {
			writeNftcheckJSON(stdout, result)
			return 1
		}
		writef(stderr, "serpent-wrt: nft check failed: missing set inet %s %s: %s\n", cfg.NftTable, cfg.NftSet, check.Error)
		return 1
	}

	if *format == "json" {
		writeNftcheckJSON(stdout, result)
		return 0
	}
	writef(stdout, "serpent-wrt: nft OK: table=%s set=%s\n", cfg.NftTable, cfg.NftSet)
	return 0
}

type nftcheckResult struct {
	Status             string `json:"status"`
	EnforcementEnabled bool   `json:"enforcement_enabled"`
	Table              string `json:"table,omitempty"`
	Set                string `json:"set,omitempty"`
	Available          bool   `json:"available"`
	TablePresent       bool   `json:"table_present"`
	SetPresent         bool   `json:"set_present"`
	Diagnostic         string `json:"diagnostic,omitempty"`
	Error              string `json:"error,omitempty"`
}

func writeNftcheckJSON(w io.Writer, result nftcheckResult) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(result)
}

func runConfigtest(args []string, stdout, stderr io.Writer, defaultConfigPath string) int {
	fs := flag.NewFlagSet("serpent-wrt configtest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "path to config file")
	effective := fs.Bool("effective", false, "print effective config after defaults and profiles")
	format := fs.String("format", "human", "output format for --effective: human or json")
	fs.Usage = func() {
		writef(stderr, "Usage: serpent-wrt configtest [--config path] [--effective] [--format human|json]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		writef(stderr, "serpent-wrt: configtest: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *format != "human" && *format != "json" {
		writef(stderr, "serpent-wrt: configtest: invalid format %q\n", *format)
		return 2
	}
	if *format == "json" && !*effective {
		writef(stderr, "serpent-wrt: configtest: --format json requires --effective\n")
		return 2
	}

	cfg, feedEntries, warnings, err := checkConfig(*cfgPath)
	if err != nil {
		if *format == "json" {
			writeConfigtestJSON(stdout, configtestResult{
				Status: "error",
				Error:  err.Error(),
			})
			return 1
		}
		writef(stderr, "serpent-wrt: configtest failed: %v\n", err)
		return 1
	}
	if *format == "json" {
		writeConfigtestJSON(stdout, configtestResult{
			Status:         "ok",
			ConfigPath:     *cfgPath,
			ThreatFeedPath: cfg.ThreatFeedPath,
			FeedEntries:    feedEntries,
			Warnings:       warnings,
			Effective:      ptr(newEffectiveConfig(cfg)),
		})
		return 0
	}
	writef(stdout, "serpent-wrt: config OK: %s (feed=%s entries=%d)\n",
		*cfgPath, cfg.ThreatFeedPath, feedEntries)
	for _, warning := range warnings {
		writef(stdout, "serpent-wrt: config warning: %s\n", warning)
	}
	if *effective {
		writef(stdout, "serpent-wrt: effective config:\n")
		if err := writeEffectiveConfig(stdout, cfg); err != nil {
			writef(stderr, "serpent-wrt: configtest failed: effective config: %v\n", err)
			return 1
		}
	}
	return 0
}

type configtestResult struct {
	Status         string           `json:"status"`
	ConfigPath     string           `json:"config_path,omitempty"`
	ThreatFeedPath string           `json:"threat_feed_path,omitempty"`
	FeedEntries    int              `json:"feed_entries,omitempty"`
	Warnings       []string         `json:"warnings,omitempty"`
	Effective      *effectiveConfig `json:"effective_config,omitempty"`
	Error          string           `json:"error,omitempty"`
}

func writeConfigtestJSON(w io.Writer, result configtestResult) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(result)
}

func ptr[T any](v T) *T {
	return &v
}

func checkConfig(path string) (*config.Config, int, []string, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("config: %w", err)
	}

	feedEntries, err := feed.ValidateFile(cfg.ThreatFeedPath)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("threat feed: %w", err)
	}
	return cfg, feedEntries, config.Warnings(cfg), nil
}

func runDaemon(cfgPath string, stderr io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		writef(stderr, "serpent-wrt: config: %v\n", err)
		return 1
	}

	var remote *events.UDPSyslog
	if cfg.SyslogTarget != "" {
		remote, err = events.NewUDPSyslog(cfg.SyslogProto, cfg.SyslogTarget)
		if err != nil {
			writef(stderr, "serpent-wrt: syslog dial %s://%s: %v (continuing without remote logging)\n",
				cfg.SyslogProto, cfg.SyslogTarget, err)
		}
	}

	log := events.NewLogger(remote)

	log.System(events.LevelInfo, events.SystemFields{
		Component: "runtime",
		Action:    "start",
		Status:    "starting",
	}, fmt.Sprintf("serpent-wrt starting (poll=%s enforcement=%v api=%v syslog=%v)",
		cfg.PollInterval, cfg.EnforcementEnabled, cfg.APIEnabled, cfg.SyslogTarget != ""))

	eng := runtime.NewEngine(cfg, log)
	eng.SetBuildInfo(runtime.BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SIGHUP → hot-reload threat feed without restart.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			_ = eng.ReloadFeed()
		}
	}()

	// Optional localhost API server.
	var apiSrv *api.Server
	if cfg.APIEnabled {
		apiSrv = api.New(cfg.APIBind, eng)
		go func() {
			log.System(events.LevelInfo, events.SystemFields{
				Component: "api",
				Action:    "listen",
				Status:    "starting",
				Addr:      cfg.APIBind,
			}, fmt.Sprintf("API listening on %s", cfg.APIBind))
			if err := apiSrv.Start(); err != nil && err != http.ErrServerClosed {
				log.System(events.LevelError, events.SystemFields{
					Component: "api",
					Action:    "listen",
					Status:    "failure",
					Error:     err.Error(),
					Addr:      cfg.APIBind,
				}, fmt.Sprintf("API listen failed: %v", err))
			}
		}()
	}

	// Graceful shutdown on SIGTERM / SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-sigCh
		log.System(events.LevelInfo, events.SystemFields{
			Component: "runtime",
			Action:    "shutdown",
			Status:    "starting",
		}, "shutting down")
		cancel()
		if apiSrv != nil {
			shutCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
			defer done()
			_ = apiSrv.Stop(shutCtx)
		}
	}()

	if err := eng.Run(ctx); err != nil {
		log.System(events.LevelError, events.SystemFields{
			Component: "runtime",
			Action:    "run",
			Status:    "failure",
			Error:     err.Error(),
		}, fmt.Sprintf("engine failed: %v", err))
		return 1
	}
	return 0
}

func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
