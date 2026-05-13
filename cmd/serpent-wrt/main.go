package main

import (
	"context"
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

	fs := flag.NewFlagSet("serpent-wrt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/serpent-wrt/serpent-wrt.yaml", "path to config file")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: serpent-wrt [--config path] [configtest]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "serpent-wrt version=%s commit=%s build_date=%s\n", version, commit, buildDate)
		return 0
	}

	if fs.NArg() > 0 {
		switch fs.Arg(0) {
		case "configtest":
			return runConfigtest(fs.Args()[1:], stdout, stderr, *cfgPath)
		default:
			fmt.Fprintf(stderr, "serpent-wrt: unknown command %q\n", fs.Arg(0))
			return 2
		}
	}

	return runDaemon(*cfgPath, stderr)
}

func runConfigtest(args []string, stdout, stderr io.Writer, defaultConfigPath string) int {
	fs := flag.NewFlagSet("serpent-wrt configtest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "path to config file")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: serpent-wrt configtest [--config path]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "serpent-wrt: configtest: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	cfg, feedEntries, err := checkConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "serpent-wrt: configtest failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "serpent-wrt: config OK: %s (feed=%s entries=%d)\n",
		*cfgPath, cfg.ThreatFeedPath, feedEntries)
	return 0
}

func checkConfig(path string) (*config.Config, int, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, 0, fmt.Errorf("config: %w", err)
	}

	feedEntries, err := feed.ValidateFile(cfg.ThreatFeedPath)
	if err != nil {
		return nil, 0, fmt.Errorf("threat feed: %w", err)
	}
	return cfg, feedEntries, nil
}

func runDaemon(cfgPath string, stderr io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "serpent-wrt: config: %v\n", err)
		return 1
	}

	var remote *events.UDPSyslog
	if cfg.SyslogTarget != "" {
		remote, err = events.NewUDPSyslog(cfg.SyslogProto, cfg.SyslogTarget)
		if err != nil {
			fmt.Fprintf(stderr, "serpent-wrt: syslog dial %s://%s: %v (continuing without remote logging)\n",
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
