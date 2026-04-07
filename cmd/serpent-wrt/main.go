package main

import (
	"context"
	"flag"
	"fmt"
	"log/syslog"
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

func main() {
	cfgPath := flag.String("config", "/etc/serpent-wrt/serpent-wrt.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serpent-wrt: config: %v\n", err)
		os.Exit(1)
	}

	var remote *syslog.Writer
	if cfg.SyslogTarget != "" {
		remote, err = syslog.Dial(cfg.SyslogProto, cfg.SyslogTarget,
			syslog.LOG_DAEMON|syslog.LOG_WARNING, "serpent-wrt")
		if err != nil {
			fmt.Fprintf(os.Stderr, "serpent-wrt: syslog dial %s://%s: %v (continuing without remote logging)\n",
				cfg.SyslogProto, cfg.SyslogTarget, err)
		}
	}

	log := events.NewLogger(remote)

	log.Info(fmt.Sprintf("serpent-wrt starting (poll=%s enforcement=%v api=%v syslog=%v)",
		cfg.PollInterval, cfg.EnforcementEnabled, cfg.APIEnabled, cfg.SyslogTarget != ""))

	eng := runtime.NewEngine(cfg, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SIGHUP → hot-reload threat feed without restart.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			if err := eng.ReloadFeed(); err != nil {
				log.Error(fmt.Sprintf("feed reload: %v", err))
			}
		}
	}()

	// Optional localhost API server.
	var apiSrv *api.Server
	if cfg.APIEnabled {
		apiSrv = api.New(cfg.APIBind, eng)
		go func() {
			log.Info(fmt.Sprintf("API listening on %s", cfg.APIBind))
			if err := apiSrv.Start(); err != nil && err != http.ErrServerClosed {
				log.Error(fmt.Sprintf("API: %v", err))
			}
		}()
	}

	// Graceful shutdown on SIGTERM / SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-sigCh
		log.Info("shutting down")
		cancel()
		if apiSrv != nil {
			shutCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
			defer done()
			_ = apiSrv.Stop(shutCtx)
		}
	}()

	if err := eng.Run(ctx); err != nil {
		log.Error(fmt.Sprintf("engine: %v", err))
		os.Exit(1)
	}
}
