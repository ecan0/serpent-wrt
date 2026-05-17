package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/feed"
)

func runFeed(args []string, stdout, stderr io.Writer, defaultConfigPath string) int {
	fs := flag.NewFlagSet("serpent-wrt feed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath, "path to config file")
	fs.Usage = func() {
		writef(stderr, "Usage: serpent-wrt feed [--config path] <list|validate|add|remove> [entry]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() == 0 {
		writef(stderr, "serpent-wrt: feed: missing command\n")
		fs.Usage()
		return 2
	}

	switch fs.Arg(0) {
	case "list":
		return runFeedList(fs.Args()[1:], stdout, stderr, *cfgPath)
	case "validate":
		return runFeedValidate(fs.Args()[1:], stdout, stderr, *cfgPath)
	case "add":
		return runFeedAdd(fs.Args()[1:], stdout, stderr, *cfgPath)
	case "remove":
		return runFeedRemove(fs.Args()[1:], stdout, stderr, *cfgPath)
	default:
		writef(stderr, "serpent-wrt: feed: unknown command %q\n", fs.Arg(0))
		return 2
	}
}

func runFeedList(args []string, stdout, stderr io.Writer, cfgPath string) int {
	if len(args) > 0 {
		writef(stderr, "serpent-wrt: feed list: unexpected argument %q\n", args[0])
		return 2
	}
	cfg, err := loadFeedConfig(cfgPath)
	if err != nil {
		writef(stderr, "serpent-wrt: feed list failed: %v\n", err)
		return 1
	}
	snap, err := feed.ListFile(cfg.ThreatFeedPath)
	if err != nil {
		writef(stderr, "serpent-wrt: feed list failed: %v\n", err)
		return 1
	}
	for _, entry := range snap.Entries {
		writef(stdout, "%s\n", entry.Value)
	}
	return 0
}

func runFeedValidate(args []string, stdout, stderr io.Writer, cfgPath string) int {
	if len(args) > 0 {
		writef(stderr, "serpent-wrt: feed validate: unexpected argument %q\n", args[0])
		return 2
	}
	cfg, err := loadFeedConfig(cfgPath)
	if err != nil {
		writef(stderr, "serpent-wrt: feed validate failed: %v\n", err)
		return 1
	}
	count, err := feed.ValidateFile(cfg.ThreatFeedPath)
	if err != nil {
		writef(stderr, "serpent-wrt: feed validate failed: %v\n", err)
		return 1
	}
	writef(stdout, "serpent-wrt: feed OK: %s entries=%d\n", cfg.ThreatFeedPath, count)
	return 0
}

func runFeedAdd(args []string, stdout, stderr io.Writer, cfgPath string) int {
	entry, ok := parseFeedEntryArg("add", args, stderr)
	if !ok {
		return 2
	}
	cfg, err := loadFeedConfig(cfgPath)
	if err != nil {
		writef(stderr, "serpent-wrt: feed add failed: %v\n", err)
		return 1
	}
	result, err := feed.AddFileEntry(cfg.ThreatFeedPath, entry.Value)
	if err != nil {
		writef(stderr, "serpent-wrt: feed add failed: %v\n", err)
		return 1
	}
	status := "added"
	if !result.Changed {
		status = "unchanged"
	}
	writef(stdout, "serpent-wrt: feed add: %s entry=%s entries=%d\n", status, entry.Value, result.Count)
	return 0
}

func runFeedRemove(args []string, stdout, stderr io.Writer, cfgPath string) int {
	entry, ok := parseFeedEntryArg("remove", args, stderr)
	if !ok {
		return 2
	}
	cfg, err := loadFeedConfig(cfgPath)
	if err != nil {
		writef(stderr, "serpent-wrt: feed remove failed: %v\n", err)
		return 1
	}
	result, err := feed.RemoveFileEntry(cfg.ThreatFeedPath, entry.Value)
	if err != nil {
		writef(stderr, "serpent-wrt: feed remove failed: %v\n", err)
		return 1
	}
	status := "removed"
	if !result.Changed {
		status = "unchanged"
	}
	writef(stdout, "serpent-wrt: feed remove: %s entry=%s entries=%d\n", status, entry.Value, result.Count)
	return 0
}

func parseFeedEntryArg(command string, args []string, stderr io.Writer) (feed.Entry, bool) {
	if len(args) == 0 {
		writef(stderr, "serpent-wrt: feed %s: missing entry\n", command)
		writef(stderr, "Usage: serpent-wrt feed %s <ip-or-cidr>\n", command)
		return feed.Entry{}, false
	}
	if len(args) > 1 {
		writef(stderr, "serpent-wrt: feed %s: unexpected argument %q\n", command, args[1])
		return feed.Entry{}, false
	}
	entry, err := feed.NormalizeEntry(args[0])
	if err != nil {
		writef(stderr, "serpent-wrt: feed %s: %v\n", command, err)
		return feed.Entry{}, false
	}
	return entry, true
}

func loadFeedConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}
