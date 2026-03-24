package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
)

func TestLoadExample(t *testing.T) {
	cfg, err := config.Load("../../configs/serpent-wrt.example.yaml")
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("poll_interval: got %v, want 5s", cfg.PollInterval)
	}
	if cfg.NftTable != "serpent_wrt" {
		t.Errorf("nft_table: got %q, want serpent_wrt", cfg.NftTable)
	}
	if cfg.NftSet != "blocked_ips" {
		t.Errorf("nft_set: got %q, want blocked_ips", cfg.NftSet)
	}
	if !cfg.APIEnabled {
		t.Error("api_enabled should be true in example config")
	}
}

func TestLoadDefaults(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./feed.txt\n")
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("load minimal config: %v", err)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("default poll_interval: got %v", cfg.PollInterval)
	}
	if cfg.NftTable != "serpent_wrt" {
		t.Errorf("default nft_table: got %q", cfg.NftTable)
	}
	if cfg.BlockDuration != time.Hour {
		t.Errorf("default block_duration: got %v", cfg.BlockDuration)
	}
}

func TestLoadMissingFeedPath(t *testing.T) {
	f := writeTemp(t, "poll_interval: 5s\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for missing threat_feed_path")
	}
}

func TestLoadInvalidCIDR(t *testing.T) {
	f := writeTemp(t, "threat_feed_path: ./f.txt\nlan_cidrs:\n  - notacidr\n")
	_, err := config.Load(f)
	if err == nil {
		t.Fatal("expected error for invalid lan_cidr")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}
