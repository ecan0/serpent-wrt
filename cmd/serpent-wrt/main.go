package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ecan0/serpent-wrt/internal/api"
	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/events"
	"github.com/ecan0/serpent-wrt/internal/runtime"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	cfgPath := flag.String("config", "/etc/serpent-wrt/serpent-wrt.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("serpent-wrt version=%s commit=%s build_date=%s\n", version, commit, buildDate)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-wrt: config: %v\n", err)
		os.Exit(1)
	}

	var remote *events.UDPSyslog
	if cfg.SyslogTarget != "" {
		remote, err = events.NewUDPSyslog(cfg.SyslogProto, cfg.SyslogTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "serpent-wrt: syslog dial %s://%s: %v (continuing without remote logging)\n",
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
		os.Exit(1)
	}
}
